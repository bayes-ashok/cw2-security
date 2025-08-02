import React, { useEffect, useState, useContext } from "react";
import axios from "axios";
import InstructorCourses from "@/components/instructor-view/courses";
import InstructorDashboard from "@/components/instructor-view/dashboard";
import AdminQuizPanel from "@/components/instructor-view/dashboard/admin-quiz-panel";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent } from "@/components/ui/tabs";
import { AuthContext } from "@/context/auth-context";
import { InstructorContext } from "@/context/instructor-context";
import { fetchInstructorCourseListService } from "@/services";
import { BarChart, Book, LogOut, List, Edit, Trash2 } from "lucide-react";
import { motion } from "framer-motion";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";


function InstructorDashboardPage() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const { resetCredentials } = useContext(AuthContext);
  const { instructorCoursesList, setInstructorCoursesList } =
    useContext(InstructorContext);
  const [quizSets, setQuizSets] = useState([]);

  async function fetchAllCourses() {
    const response = await fetchInstructorCourseListService();
    if (response?.success) setInstructorCoursesList(response?.data);
  }

  async function handleDeleteQuiz(quizId) {
    try {
      const response = await axios.delete(
        `http://localhost:8000/instructor/quiz/delete/${quizId}`
      );
  
      if (response.status === 200) {
        // Remove the deleted quiz from the state
        setQuizSets((prevQuizzes) => prevQuizzes.filter((quiz) => quiz._id !== quizId));
  
        toast.success("Delete successful! 🎉", { position: "top-right" });

      }
    } catch (error) {
      console.error("Error deleting quiz", error);
      toast.error("Failed to delete quiz. Please try again.", {
        position: "top-right",
        autoClose: 3000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        theme: "colored",
      });
    }
  }
  

  async function fetchQuizSets() {
    try {
      const response = await axios.get("http://localhost:8000/instructor/quiz");
      setQuizSets(response.data.data);
    } catch (error) {
      console.error("Error fetching quizzes", error);
    }
  }

  useEffect(() => {
    fetchAllCourses();
    fetchQuizSets();
  }, []);

  const menuItems = [
    {
      icon: BarChart,
      label: "Dashboard",
      value: "dashboard",
      component: <InstructorDashboard listOfCourses={instructorCoursesList} />,
    },
    {
      icon: Book,
      label: "Courses",
      value: "courses",
      component: <InstructorCourses listOfCourses={instructorCoursesList} />,
    },
    {
      icon: LogOut,
      label: "Logout",
      value: "logout",
      component: null,
    },
  ];

  function handleLogout() {
    resetCredentials();
    sessionStorage.clear();
  }

  return (
    <div className="flex h-screen bg-gray-50 text-gray-900">
      {/* Sidebar - Fixed & Always Visible */}
      <motion.aside className="w-72 bg-white shadow-xl h-full p-6 rounded-r-2xl border-r border-gray-300">
        <h2 className="text-2xl font-semibold mb-6 text-gray-900">
          Instructor Panel
        </h2>
        <nav className="space-y-2">
          {menuItems.map((menuItem) => (
            <Button
              key={menuItem.value}
              className={`w-full flex items-center gap-3 p-3 rounded-lg transition ${
                activeTab === menuItem.value
                  ? "bg-blue-600 text-white"
                  : "bg-gray-300 text-gray-900 hover:bg-gray-400"
              }`}
              onClick={
                menuItem.value === "logout"
                  ? handleLogout
                  : () => setActiveTab(menuItem.value)
              }
            >
              {menuItem.icon && (
                <menuItem.icon className="w-5 h-5 text-gray-900" />
              )}
              {menuItem.label}
            </Button>
          ))}
        </nav>
      </motion.aside>

      {/* Main Content */}
      <main className="flex-1 p-12 overflow-y-auto bg-gray-100">
        <div className="max-w-7xl mx-auto">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            {menuItems.map((menuItem) => (
              <TabsContent value={menuItem.value} key={menuItem.value}>
                {menuItem.component !== null ? menuItem.component : null}
              </TabsContent>
            ))}
            {activeTab === "add-quiz" && <AdminQuizPanel />}
          </Tabs>
        </div>
      </main>
    </div>
  );
}

export default InstructorDashboardPage;
