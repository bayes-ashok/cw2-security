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
import { signInFormControls, signUpFormControls } from "@/config";

function AuthPage() {
  const [activeTab, setActiveTab] = useState("signin");
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    label: "",
    color: "",
  });
  const [suggestedPassword, setSuggestedPassword] = useState("");
  const {
    signInFormData,
    setSignInFormData,
    signUpFormData,
    setSignUpFormData,
    handleRegisterUser,
    handleLoginUser,
  } = useContext(AuthContext);

  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const [captchaToken, setCaptchaToken] = useState(null);

  const checkPasswordStrength = (password) => {
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

  const generatePassword = () => {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    let password = "";
    for (let i = 0; i < 12; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    if (!/[A-Z]/.test(password)) password = password.slice(0, -1) + "A";
    if (!/[a-z]/.test(password)) password = password.slice(0, -1) + "a";
    if (!/[0-9]/.test(password)) password = password.slice(0, -1) + "1";
    if (!/[^A-Za-z0-9]/.test(password)) password = password.slice(0, -1) + "@";
    return password;
  };

  const handlePasswordFocus = () => {
    if (activeTab === "signup") {
      setSuggestedPassword(generatePassword());
    }
  };

  const handleSuggestedPasswordClick = () => {
    setSignUpFormData({ ...signUpFormData, password: suggestedPassword });
    setSuggestedPassword("");
  };

  useEffect(() => {
    if (activeTab === "signup" && signUpFormData.password) {
      setPasswordStrength(checkPasswordStrength(signUpFormData.password));
    } else {
      setPasswordStrength({ score: 0, label: "", color: "" });
      setSuggestedPassword("");
    }
  }, [signUpFormData.password, activeTab]);

  function handleTabChange(value) {
    setActiveTab(value);
    setSuggestedPassword("");
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
      signUpFormData.password !== "" &&
      passwordStrength.score >= 3 &&
      captchaToken
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
    if (control.name === "password") {
      return { ...control, autocomplete: "new-password" };
    }
    return control;
  });

  const passwordStrengthContent = activeTab === "signup" && (
    <div className="space-y-2">
      {signUpFormData.password && (
        <>
          <div className="text-sm font-medium text-gray-700">
            Password Strength: {passwordStrength.label}
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5">
            <div
              className={`h-2.5 rounded-full ${passwordStrength.color}`}
              style={{ width: `${(passwordStrength.score / 6) * 100}%` }}
            ></div>
          </div>
        </>
      )}
      {suggestedPassword && (
        <div className="text-sm text-gray-600">
          Suggested Password:{" "}
          <span
            className="text-blue-600 cursor-pointer hover:underline"
            onClick={handleSuggestedPasswordClick}
          >
            {suggestedPassword}
          </span>
        </div>
      )}
    </div>
  );

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
            <span className="font-extrabold text-3xl">Sikshyalaya</span>
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
                    with at least 8 characters, including uppercase, lowercase,
                    numbers, and special characters.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <CommonForm
                    formControls={enhancedSignUpFormControls}
                    buttonText={"Sign Up"}
                    formData={signUpFormData}
                    setFormData={setSignUpFormData}
                    isButtonDisabled={!checkIfSignUpFormIsValid()}
                    handleSubmit={(e) => handleRegisterUser(e, captchaToken)}
                    customContent={passwordStrengthContent}
                    onPasswordFocus={handlePasswordFocus}
                  />
                  <ReCAPTCHA
                    sitekey="6LdIKZMrAAAAAFcY_KH5cgOZV7IvLKvgVm9CE0d1"
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
        </div>
      </div>
    </div>
  );
}

export default AuthPage;
