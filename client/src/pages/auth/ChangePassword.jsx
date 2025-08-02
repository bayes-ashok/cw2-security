import { useContext, useState, useEffect } from "react";
import { AuthContext } from "@/context/auth-context";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import CommonForm from "@/components/common-form";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";

const changePasswordFormControls = [
  {
    name: "currentPassword",
    label: "Current Password",
    type: "password",
    placeholder: "Enter current password",
    componentType: "input",
  },
  {
    name: "password",
    label: "New Password",
    type: "password",
    placeholder: "Enter new password",
    componentType: "input",
  },
];

function ChangePassword() {
  const { updateUserDetails } = useContext(AuthContext);
  const [formData, setFormData] = useState({
    currentPassword: "",
    password: "",
  });
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    label: "",
    color: "",
  });
  const [suggestedPassword, setSuggestedPassword] = useState("");
  const navigate = useNavigate();

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
    setSuggestedPassword(generatePassword());
  };

  const handleSuggestedPasswordClick = () => {
    setFormData({ ...formData, password: suggestedPassword });
    setSuggestedPassword("");
  };

  useEffect(() => {
    if (formData.password) {
      setPasswordStrength(checkPasswordStrength(formData.password));
    } else {
      setPasswordStrength({ score: 0, label: "", color: "" });
      setSuggestedPassword("");
    }
  }, [formData.password]);

  const checkIfFormIsValid = () => {
    return (
      formData.currentPassword !== "" &&
      formData.password !== "" &&
      passwordStrength.score >= 3
    );
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const data = await updateUserDetails(formData);
      if (data.success) {
        toast.success(data.message || "Password updated successfully! 🎉", {
          position: "top-right",
        });
        navigate("/"); // Redirect to home or dashboard
      } else {
        toast.error(data.message || "Failed to update password.", {
          position: "top-right",
        });
      }
    } catch (error) {
      toast.error(
        error?.response?.data?.message || "Failed to update password.",
        { position: "top-right" }
      );
    }
  };

  const passwordStrengthContent = (
    <div className="space-y-2">
      {formData.password && (
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
      <header className="flex items-center justify-between p-3 border-b bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg">
        <div className="flex items-center space-x-4">
          <a
            href="/home"
            className="flex items-center hover:text-gray-200 transition-all"
          >
            <span className="font-extrabold text-3xl">Sikshyalaya</span>
          </a>
        </div>
      </header>
      <div className="flex items-center justify-center mt-3">
        <Card className="w-full max-w-lg bg-white rounded-lg shadow-lg border border-gray-200">
          <CardHeader>
            <CardTitle className="text-gray-900 text-xl font-semibold">
              Change Password
            </CardTitle>
            <CardDescription className="text-gray-600">
              Your password has expired. Please set a new password to continue.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <CommonForm
              formControls={changePasswordFormControls}
              buttonText={"Update Password"}
              formData={formData}
              setFormData={setFormData}
              isButtonDisabled={!checkIfFormIsValid()}
              handleSubmit={handleSubmit}
              customContent={passwordStrengthContent}
              onPasswordFocus={handlePasswordFocus}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default ChangePassword;