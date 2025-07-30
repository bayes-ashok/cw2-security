import { Skeleton } from "@/components/ui/skeleton";
import { initialSignInFormData, initialSignUpFormData } from "@/config";
import { checkAuthService, loginService, registerService, verifyOtpService } from "@/services";
import { createContext, useEffect, useState } from "react";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css"; // Import the toast styles

export const AuthContext = createContext(null);

export default function AuthProvider({ children }) {
  const [signInFormData, setSignInFormData] = useState(initialSignInFormData);
  const [signUpFormData, setSignUpFormData] = useState(initialSignUpFormData);
  const [auth, setAuth] = useState({
    authenticate: false,
    user: null,
  });
  const [loading, setLoading] = useState(true);
  const [otpRequired, setOtpRequired] = useState(false);
  const [otpFormData, setOtpFormData] = useState({ otp: "" });
  const [userId, setUserId] = useState(null);

  // Register user and show a success/error toast
  async function handleRegisterUser(event, captchaToken) {
    event.preventDefault();

    try {
      const data = await registerService(signUpFormData, captchaToken);

      if (data.success) {
        toast.success(data.message || "Signup successful! 🎉", {
          position: "top-right",
        });
        // Reset signup form data after success
        setSignUpFormData(initialSignUpFormData);
      } else {
        toast.error(data.message || "Signup failed. Please try again.", {
          position: "top-right",
        });
      }
    } catch (error) {
      toast.error(
        error?.response?.data?.message || "Signup failed. Please try again.",
        { position: "top-right" }
      );
    }
  }

  // Login user and handle OTP if required
  async function handleLoginUser(event) {
    event.preventDefault();

    try {
      const data = await loginService(signInFormData);

      if (data.success) {
        if (data.data.requiresOtp) {
          setOtpRequired(true);
          setUserId(data.data.userId);
          toast.info(data.message || "Please enter the OTP sent to your email.", {
            position: "top-right",
          });
        } else {
          sessionStorage.setItem(
            "accessToken",
            JSON.stringify(data.data.accessToken)
          );
          setAuth({
            authenticate: true,
            user: data.data.user,
          });
          toast.success(data.message || "Login successful! 🎉", {
            position: "top-right",
          });
          // Reset signin form data after successful login
          setSignInFormData(initialSignInFormData);
        }
      } else {
        setAuth({
          authenticate: false,
          user: null,
        });
        toast.error(
          data.message || "Login failed. Please check your credentials.",
          { position: "top-right" }
        );
      }
    } catch (error) {
      toast.error(
        error?.response?.data?.message || "Login failed. Please try again.",
        { position: "top-right" }
      );
    }
  }

  // Verify OTP
  async function handleVerifyOtp(event) {
    event.preventDefault();

    try {
      const data = await verifyOtpService({ userId, otp: otpFormData.otp });
      if (data.success) {
        sessionStorage.setItem(
          "accessToken",
          JSON.stringify(data.data.accessToken)
        );
        setAuth({
          authenticate: true,
          user: data.data.user,
        });
        setOtpRequired(false);
        setOtpFormData({ otp: "" }); // Already resets OTP form
        setUserId(null);
        toast.success(data.message || "OTP verified! Login successful! 🎉", {
          position: "top-right",
        });
      } else {
        toast.error(data.message || "Invalid OTP. Please try again.", {
          position: "top-right",
        });
      }
    } catch (error) {
      toast.error(
        error?.response?.data?.message || "OTP verification failed. Please try again.",
        { position: "top-right" }
      );
    }
  }

  // Check user authentication
  async function checkAuthUser() {
    try {
      const data = await checkAuthService();
      if (data.success) {
        setAuth({
          authenticate: true,
          user: data.data.user,
        });
        setLoading(false);
      } else {
        setAuth({
          authenticate: false,
          user: null,
        });
        setLoading(false);
      }
    } catch (error) {
      console.log(error);
      if (!error?.response?.data?.success) {
        setAuth({
          authenticate: false,
          user: null,
        });
        setLoading(false);
      }
    }
  }

  // Reset credentials
  function resetCredentials() {
    setAuth({
      authenticate: false,
      user: null,
    });
    setOtpRequired(false);
    setOtpFormData({ otp: "" });
    setUserId(null);
    setSignInFormData(initialSignInFormData);
    setSignUpFormData(initialSignUpFormData);
  }

  useEffect(() => {
    checkAuthUser();
  }, []);

  return (
    <AuthContext.Provider
      value={{
        signInFormData,
        setSignInFormData,
        signUpFormData,
        setSignUpFormData,
        handleRegisterUser,
        handleLoginUser,
        handleVerifyOtp,
        auth,
        resetCredentials,
        otpRequired,
        otpFormData,
        setOtpFormData,
      }}
    >
      {loading ? <Skeleton /> : children}
      <ToastContainer />
    </AuthContext.Provider>
  );
}