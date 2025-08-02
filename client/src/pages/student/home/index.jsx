import { courseCategories } from "@/config";
import banner from "../../../../public/banner-img.png";
import { Button } from "@/components/ui/button";
import { useContext, useEffect } from "react";
import { StudentContext } from "@/context/student-context";
import {
  checkCoursePurchaseInfoService,
  fetchStudentViewCourseListService,
} from "@/services";
import { AuthContext } from "@/context/auth-context";
import { useNavigate } from "react-router-dom";

function StudentHomePage() {
  const { studentViewCoursesList, setStudentViewCoursesList } =
    useContext(StudentContext);
  const { auth } = useContext(AuthContext);
  const navigate = useNavigate();

  function handleNavigateToCoursesPage(getCurrentId) {
    console.log(getCurrentId);
    sessionStorage.removeItem("filters");
    const currentFilter = {
      category: [getCurrentId],
    };

    sessionStorage.setItem("filters", JSON.stringify(currentFilter));

    navigate("/courses");
  }

  async function fetchAllStudentViewCourses() {
    const response = await fetchStudentViewCourseListService();
    if (response?.success) setStudentViewCoursesList(response?.data);
  }

  async function handleCourseNavigate(getCurrentCourseId) {
    const response = await checkCoursePurchaseInfoService(
      getCurrentCourseId,
      auth?.user?._id
    );

    if (response?.success) {
      if (response?.data) {
        navigate(`/course-progress/${getCurrentCourseId}`);
      } else {
        navigate(`/course/details/${getCurrentCourseId}`);
      }
    }
  }

  useEffect(() => {
    fetchAllStudentViewCourses();
  }, []);

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900 flex flex-col">
      {/* Main Content */}
      <main className="flex-grow">
        {/* Hero Section */}
        <section className="w-full min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-white px-6 lg:px-24">
          <div className="max-w-6xl mx-auto flex flex-col items-center text-center">
            <h1 className="text-5xl sm:text-6xl font-extrabold leading-tight mb-6">
              Crack <span className="text-blue-600">Loksewa Exams</span> with
              Confidence
            </h1>
            <p className="text-lg text-gray-700 max-w-3xl mb-8">
              Access high-quality{" "}
              <span className="font-semibold">lecture videos</span> &{" "}
              <span className="font-semibold">quiz sets</span> designed for
              Loksewa success. Learn smarter, practice better, and{" "}
              <span className="font-semibold text-blue-600">
                achieve your dream job
              </span>{" "}
              in Nepal's civil service.
            </p>
            <div className="flex flex-wrap justify-center gap-5">
              <button className="px-7 py-3 text-lg font-semibold text-white bg-blue-600 rounded-lg shadow-md transition hover:bg-blue-700">
                Get Started
              </button>
              <button className="px-7 py-3 text-lg font-semibold text-blue-600 border border-blue-600 bg-white rounded-lg shadow-md transition hover:bg-blue-100">
                Explore Courses
              </button>
            </div>
          </div>
        </section>

        {/* Course Categories - Soft Blue Background */}
        <section className="py-12 px-6 lg:px-16 bg-blue-50 border-t border-gray-200">
          <h2 className="text-3xl font-semibold mb-8 text-gray-900 text-center">
            Course Categories
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-6 max-w-5xl mx-auto">
            {courseCategories.map((categoryItem) => (
              <Button
                key={categoryItem.id}
                onClick={() => handleNavigateToCoursesPage(categoryItem.id)}
                className="flex items-center justify-start w-full bg-white hover:bg-blue-100 focus:ring-2 focus:ring-blue-400 text-gray-900 border border-gray-300 rounded-lg px-5 py-3 transition-all duration-200 shadow-sm"
                aria-label={`View courses in ${categoryItem.label}`}
              >
                {categoryItem.label}
              </Button>
            ))}
          </div>
        </section>

        {/* Featured Courses - White Background */}
        <section className="py-12 px-5 lg:px-10 bg-white border-t border-gray-200">
          <h2 className="text-3xl font-semibold mb-8 text-gray-900 text-center">
            Featured Courses
          </h2>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-6 max-w-6xl mx-auto">
            {studentViewCoursesList && studentViewCoursesList.length > 0 ? (
              studentViewCoursesList.map((courseItem) => (
                <div
                  key={courseItem?._id}
                  onClick={() => handleCourseNavigate(courseItem?._id)}
                  className="border border-gray-200 rounded-lg overflow-hidden shadow-sm cursor-pointer bg-white hover:shadow-md hover:-translate-y-1 transition-transform duration-200 ease-in-out"
                  role="button"
                  tabIndex={0}
                  aria-label={`View details for ${courseItem?.title}`}
                >
                  <img
                    src={courseItem?.image}
                    alt={courseItem?.title}
                    width={250}
                    height={120}
                    className="w-full h-32 object-cover rounded-t-lg"
                  />
                  <div className="p-4">
                    <h3 className="font-medium text-[15px] text-gray-900 truncate">
                      {courseItem?.title}
                    </h3>
                    <p className="text-xs text-gray-600 mb-1">
                      {courseItem?.instructorName}
                    </p>
                    <p className="font-bold text-sm text-blue-600">
                      Rs. {courseItem?.pricing}
                    </p>
                  </div>
                </div>
              ))
            ) : (
              <h1 className="text-gray-600 text-center col-span-full">
                No Courses Found
              </h1>
            )}
          </div>
        </section>
      </main>

      {/* Footer Section */}
      <footer className="bg-blue-600 text-white py-10">
        <div className="max-w-6xl mx-auto px-6 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-8">
          {/* About Section */}
          <div>
            <h3 className="text-lg font-bold mb-3">Loksewa Academy</h3>
            <p className="text-sm text-white/80">
              Your trusted partner in Loksewa exam preparation. Learn, practice,
              and succeed!
            </p>
          </div>

          {/* Quick Links */}
          <div>
            <h3 className="text-lg font-bold mb-3">Quick Links</h3>
            <ul className="space-y-2">
              <li>
                <a
                  href="#"
                  className="text-white/80 hover:text-white transition"
                >
                  Home
                </a>
              </li>
              <li>
                <a
                  href="#"
                  className="text-white/80 hover:text-white transition"
                >
                  Courses
                </a>
              </li>
              <li>
                <a
                  href="#"
                  className="text-white/80 hover:text-white transition"
                >
                  About Us
                </a>
              </li>
              <li>
                <a
                  href="#"
                  className="text-white/80 hover:text-white transition"
                >
                  Contact
                </a>
              </li>
            </ul>
          </div>

          {/* Social Media */}
          <div>
            <h3 className="text-lg font-bold mb-3">Follow Us</h3>
            <div className="flex space-x-4">
              {/* Facebook */}
              <a href="#" className="hover:opacity-80 transition">
                <svg
                  className="w-6 h-6 text-white"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M22 12c0-5.523-4.477-10-10-10S2 6.477 2 12c0 4.991 3.657 9.128 8.438 9.878v-6.987H7.898v-2.89h2.54v-2.198c0-2.506 1.492-3.89 3.777-3.89 1.095 0 2.238.195 2.238.195v2.465h-1.26c-1.244 0-1.63.775-1.63 1.567v1.861h2.773l-.443 2.89h-2.33v6.987C18.343 21.128 22 16.991 22 12z" />
                </svg>
              </a>
              {/* Twitter */}
              <a href="#" className="hover:opacity-80 transition">
                <svg
                  className="w-6 h-6 text-white"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M8.29 20.251c7.547 0 11.675-6.253 11.675-11.675 0-.178 0-.355-.012-.532A8.347 8.347 0 0022 5.92a8.19 8.19 0 01-2.357.646 4.107 4.107 0 001.804-2.27 8.221 8.221 0 01-2.605.996 4.1 4.1 0 00-6.985 3.742 11.646 11.646 0 01-8.457-4.287 4.102 4.102 0 001.27 5.466A4.072 4.072 0 012 9.557v.051a4.1 4.1 0 003.292 4.016 4.095 4.095 0 01-1.853.07 4.105 4.105 0 003.832 2.849A8.221 8.221 0 012 18.116a11.616 11.616 0 006.29 1.843" />
                </svg>
              </a>
              {/* LinkedIn */}
              <a href="#" className="hover:opacity-80 transition">
                <svg
                  className="w-6 h-6 text-white"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M19 3A2 2 0 0121 5v14a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h14zm-3.5 16v-6.205c0-1.554-.544-2.617-1.902-2.617-1.038 0-1.656.7-1.93 1.374-.099.238-.123.57-.123.9V19H8.5v-8h2.867v1.145h.04c.398-.755 1.37-1.54 2.823-1.54 2.014 0 3.37 1.298 3.37 4.088V19H15.5zM5.5 8h3V19h-3V8zm1.5-3.5a1.5 1.5 0 100 3 1.5 1.5 0 000-3z" />
                </svg>
              </a>
              {/* Instagram */}
              <a href="#" className="hover:opacity-80 transition">
                <svg
                  className="w-6 h-6 text-white"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M7 2h10a5 5 0 015 5v10a5 5 0 01-5 5H7a5 5 0 01-5-5V7a5 5 0 015-5zm8 3a1 1 0 100 2 1 1 0 000-2zm-5 2a5 5 0 105 5 5 5 0 00-5-5zm0 8a3 3 0 113-3 3 3 0 01-3 3z" />
                </svg>
              </a>
            </div>
          </div>
        </div>

        {/* Copyright */}
        <div className="mt-8 text-center text-sm text-white/80 border-t border-white/20 pt-4">
          © {new Date().getFullYear()} Loksewa Academy. All Rights Reserved.
        </div>
      </footer>
    </div>
  );
}

export default StudentHomePage;
