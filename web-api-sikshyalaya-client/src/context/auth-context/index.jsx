import { Skeleton } from "@/components/ui/skeleton";
import { initialSignInFormData, initialSignUpFormData } from "@/config";
import { checkAuthService, loginService, registerService } from "@/services";
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

  // Register user and show a success/error toast
  async function handleRegisterUser(event, captchaToken) {
    event.preventDefault();

    try {
      // ✅ Send captchaToken with signup data
      const data = await registerService(signUpFormData, captchaToken );

      if (data.success) {
        toast.success(data.message || "Signup successful! 🎉", {
          position: "top-right",
        });
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
  async function handleLoginUser(event) {
    event.preventDefault();
    console.log(signInFormData);

    try {
      const data = await loginService(signInFormData); // ✅ no captcha now
      console.log(signInFormData);

      if (data.success) {
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
  }

  useEffect(() => {
    checkAuthUser();
  }, []);

  console.log(auth, "gf");

  return (
    <AuthContext.Provider
      value={{
        signInFormData,
        setSignInFormData,
        signUpFormData,
        setSignUpFormData,
        handleRegisterUser,
        handleLoginUser,
        auth,
        resetCredentials,
      }}
    >
      {loading ? <Skeleton /> : children}
      <ToastContainer /> {/* Add ToastContainer to render the toasts */}
    </AuthContext.Provider>
  );
}
