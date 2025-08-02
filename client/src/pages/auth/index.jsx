import { GraduationCap, Moon, Menu } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { useContext, useState, useEffect } from "react";
import { AuthContext } from "@/context/auth-context";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import ReCAPTCHA from "react-google-recaptcha";
import CommonForm from "@/components/common-form";
import {
  signInFormControls,
  signUpFormControls,
  otpFormControls,
} from "@/config";
import DOMPurify from "dompurify";

function AuthPage() {
  const [activeTab, setActiveTab] = useState("signin");
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    label: "",
    color: "",
  });
  const [successMessage, setSuccessMessage] = useState("");
  const {
    signInFormData,
    setSignInFormData,
    signUpFormData,
    setSignUpFormData,
    handleRegisterUser,
    handleLoginUser,
    handleVerifyOtp,
    otpRequired,
    otpFormData,
    setOtpFormData,
  } = useContext(AuthContext);

  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const [captchaToken, setCaptchaToken] = useState(null);

  const checkPasswordStrength = (password, fName, email) => {
    // Check if password contains user's name or email
    const sanitizedFName = DOMPurify.sanitize(fName || "").toLowerCase();
    const sanitizedEmail = DOMPurify.sanitize(email || "").toLowerCase();
    const sanitizedPassword = DOMPurify.sanitize(password || "").toLowerCase();

    if (
      (sanitizedFName && sanitizedPassword.includes(sanitizedFName)) ||
      (sanitizedEmail &&
        sanitizedPassword.includes(sanitizedEmail.split("@")[0]))
    ) {
      return {
        score: 0,
        label: "Invalid: Password cannot contain your name or email",
        color: "bg-red-500",
      };
    }

    let score = 0;
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    let label, color;
    if (score <= 2) {
      label = "Weak";
      color = "bg-red-500";
    } else if (score <= 4) {
      label = "Medium";
      color = "bg-yellow-500";
    } else {
      label = "Strong";
      color = "bg-green-500";
    }
    return { score, label, color };
  };

  useEffect(() => {
    if (activeTab === "signup" && signUpFormData.password) {
      setPasswordStrength(
        checkPasswordStrength(
          signUpFormData.password,
          signUpFormData.fName,
          signUpFormData.email
        )
      );
    } else {
      setPasswordStrength({ score: 0, label: "", color: "" });
    }
  }, [
    signUpFormData.password,
    signUpFormData.fName,
    signUpFormData.email,
    activeTab,
  ]);

  function handleTabChange(value) {
    setActiveTab(value);
    setSuccessMessage("");
  }

  function checkIfSignInFormIsValid() {
    return (
      signInFormData &&
      signInFormData.email !== "" &&
      signInFormData.password !== ""
    );
  }

  function checkIfSignUpFormIsValid() {
    return (
      signUpFormData &&
      signUpFormData.fName !== "" &&
      signUpFormData.email !== "" &&
      signUpFormData.phone !== "" &&
      signUpFormData.password !== "" &&
      passwordStrength.score >= 3 &&
      !passwordStrength.label.includes("Invalid") &&
      captchaToken
    );
  }

  function checkIfOtpFormIsValid() {
    return (
      otpFormData && otpFormData.otp !== "" && otpFormData.otp.length === 6
    );
  }

  const enhancedSignInFormControls = signInFormControls.map((control) => {
    if (control.name === "email") {
      return { ...control, autocomplete: "email" };
    }
    if (control.name === "password") {
      return { ...control, autocomplete: "current-password" };
    }
    return control;
  });

  const enhancedSignUpFormControls = signUpFormControls.map((control) => {
    if (control.name === "email") {
      return { ...control, autocomplete: "email" };
    }
    if (control.name === "phone") {
      return { ...control, autocomplete: "tel" };
    }
    if (control.name === "password") {
      return { ...control, autocomplete: "new-password" };
    }
    return control;
  });

  const passwordStrengthContent = activeTab === "signup" && (
    <div className="space-y-2">
      {signUpFormData.password && (
        <>
          <div
            className={`text-sm font-medium ${
              passwordStrength.label.includes("Invalid")
                ? "text-red-600"
                : "text-gray-700"
            }`}
            dangerouslySetInnerHTML={{
              __html: DOMPurify.sanitize(
                `Password Strength: ${passwordStrength.label}`
              ),
            }}
          />
          {!passwordStrength.label.includes("Invalid") && (
            <div className="w-full bg-gray-200 rounded-full h-2.5">
              <div
                className={`h-2.5 rounded-full ${passwordStrength.color}`}
                style={{ width: `${(passwordStrength.score / 6) * 100}%` }}
              ></div>
            </div>
          )}
        </>
      )}
    </div>
  );

  const handleSignUpSubmit = async (e) => {
    const result = await handleRegisterUser(e, captchaToken);
    if (result.success) {
      setSuccessMessage("Registration successful! Please sign in.");
      setActiveTab("signin");
      setCaptchaToken(null);
    } else {
      setSuccessMessage("Registration failed. Please try again.");
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-gradient-to-b from-gray-100 to-gray-50">
      <header className="flex items-center justify-between p-3 border-b bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg relative">
        <div className="flex items-center space-x-4">
          <button onClick={() => setMenuOpen(!menuOpen)} className="md:hidden">
            <Menu className="w-7 h-7" />
          </button>
          <Link
            to="/home"
            className="flex items-center hover:text-gray-200 transition-all"
          >
            <GraduationCap className="h-9 w-9 mr-3" />
            <span className="font-extrabold text-3xl">Padhnapaiincha</span>
          </Link>
        </div>
        <div className="flex items-center space-x-4">
          <button className="p-2 rounded-full bg-white/20 hover:bg-white/30 transition transform hover:scale-110">
            <Moon className="w-7 h-7" />
          </button>
        </div>
      </header>

      <div className="flex items-center justify-center mt-3">
        <div className="w-full max-w-lg bg-gray-50 p-3 rounded-2xl shadow-lg border border-gray-200">
          {otpRequired ? (
            <Card className="bg-white rounded-lg">
              <CardHeader>
                <CardTitle className="text-gray-900 text-xl font-semibold">
                  Verify OTP
                </CardTitle>
                <CardDescription className="text-gray-600">
                  Enter the 6-digitOTP sent to your email to complete login.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <CommonForm
                  formControls={otpFormControls}
                  buttonText={"Verify OTP"}
                  formData={otpFormData}
                  setFormData={setOtpFormData}
                  isButtonDisabled={!checkIfOtpFormIsValid()}
                  handleSubmit={handleVerifyOtp}
                />
              </CardContent>
            </Card>
          ) : (
            <Tabs
              value={activeTab}
              defaultValue="signin"
              onValueChange={handleTabChange}
              className="w-full"
            >
              <TabsList className="grid w-full grid-cols-2 bg-gray-100 rounded-lg">
                <TabsTrigger
                  value="signin"
                  className="rounded-md text-gray-700 hover:bg-gray-200"
                >
                  Sign In
                </TabsTrigger>
                <TabsTrigger
                  value="signup"
                  className="rounded-md text-gray-700 hover:bg-gray-200"
                >
                  Sign Up
                </TabsTrigger>
              </TabsList>
              <TabsContent value="signin">
                <Card className="bg-white rounded-lg">
                  <CardHeader>
                    <CardTitle className="text-gray-900 text-xl font-semibold">
                      Sign in to your account
                    </CardTitle>
                    <CardDescription className="text-gray-600">
                      Enter your email and password to access your account
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <CommonForm
                      formControls={enhancedSignInFormControls}
                      buttonText={"Login"}
                      formData={signInFormData}
                      setFormData={setSignInFormData}
                      isButtonDisabled={!checkIfSignInFormIsValid()}
                      handleSubmit={handleLoginUser}
                    />
                  </CardContent>
                </Card>
              </TabsContent>
              <TabsContent value="signup">
                <Card className="bg-white rounded-lg">
                  <CardHeader>
                    <CardTitle className="text-gray-900 text-xl font-semibold">
                      Create a new account
                    </CardTitle>
                    <CardDescription className="text-gray-600">
                      Enter your details to get started. Use a strong password
                      with at least 8 characters, including uppercase,
                      lowercase, numbers, and special characters. Password
                      cannot contain your name or email.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {successMessage && (
                      <div
                        className={`text-sm ${
                          successMessage.includes("failed")
                            ? "text-red-600"
                            : "text-green-600"
                        }`}
                        dangerouslySetInnerHTML={{
                          __html: DOMPurify.sanitize(successMessage),
                        }}
                      />
                    )}
                    <CommonForm
                      formControls={enhancedSignUpFormControls}
                      buttonText={"Sign Up"}
                      formData={signUpFormData}
                      setFormData={setSignUpFormData}
                      isButtonDisabled={!checkIfSignUpFormIsValid()}
                      handleSubmit={handleSignUpSubmit}
                      customContent={passwordStrengthContent}
                    />
                    <ReCAPTCHA
                      sitekey={process.env.REACT_APP_RECAPTCHA_SITE_KEY}
                      onChange={(token) => {
                        console.log("reCAPTCHA token:", token);
                        setCaptchaToken(token);
                      }}
                      onExpired={() => {
                        console.log("reCAPTCHA token expired");
                        setCaptchaToken(null);
                      }}
                    />
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          )}
        </div>
      </div>
    </div>
  );
}

export default AuthPage;
