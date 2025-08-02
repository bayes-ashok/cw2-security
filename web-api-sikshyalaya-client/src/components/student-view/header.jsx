import { GraduationCap, TvMinimalPlay, Sun, Moon, ClipboardList, Menu } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "../ui/button";
import { useContext, useState } from "react";
import { AuthContext } from "@/context/auth-context";

function StudentViewCommonHeader() {
  const navigate = useNavigate();
  const { resetCredentials } = useContext(AuthContext);
  const [menuOpen, setMenuOpen] = useState(false);

  function handleLogout() {
    resetCredentials();
    sessionStorage.clear();
  }

  return (
    <header className="flex items-center justify-between p-3 border-b bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg relative">
      {/* Logo Section */}
      <div className="flex items-center space-x-4">
        <button onClick={() => setMenuOpen(!menuOpen)} className="md:hidden">
          <Menu className="w-7 h-7" />
        </button>
        <Link to="/home" className="flex items-center hover:text-gray-200 transition-all">
          <GraduationCap className="h-9 w-9 mr-3" />
          <span className="font-extrabold text-3xl">Padhnapaiincha</span>
        </Link>
      </div>

      {/* Center Navigation */}
      <nav className="hidden md:flex space-x-6">
        <Button
          variant="ghost"
          onClick={() => navigate("/courses")}
          className="text-xl font-bold transform transition-all hover:scale-105"
        >
          Courses
        </Button>
        <Button
          variant="ghost"
          onClick={() => navigate("/profile")}
          className="text-xl font-bold transform transition-all hover:scale-105"
        >
          My Profile
        </Button>
        <Button
          variant="ghost"
          onClick={() => navigate("/student-courses")}
          className="text-xl font-bold transform transition-all hover:scale-105"
        >
          My Learning
        </Button>
      </nav>

      {/* User Actions */}
      <div className="flex items-center space-x-4">
        <button
          className="p-2 rounded-full bg-white/20 hover:bg-white/30 transition transform hover:scale-110"
        >
          <Moon className="w-7 h-7" />
        </button>
        <Button onClick={handleLogout} className="bg-red-500 hover:bg-red-600 text-white font-bold text-lg px-6 py-2 rounded-md shadow-lg transition-all transform hover:scale-105">
          Logout
        </Button>
      </div>

      {/* Mobile Navigation */}
      {menuOpen && (
        <div className="absolute top-full left-0 w-full bg-blue-700 p-4 flex flex-col space-y-4 md:hidden">
          <Button variant="ghost" onClick={() => navigate("/courses")} className="text-xl font-bold text-white transform transition-all hover:scale-105">
            Courses
          </Button>
          <Button variant="ghost" onClick={() => navigate("/quiz")} className="text-xl font-bold text-white transform transition-all hover:scale-105">
            Quiz Hub
          </Button>
          <Button variant="ghost" onClick={() => navigate("/student-courses")} className="text-xl font-bold text-white transform transition-all hover:scale-105">
            My Learning
          </Button>
        </div>
      )}
    </header>
  );
}

export default StudentViewCommonHeader;
