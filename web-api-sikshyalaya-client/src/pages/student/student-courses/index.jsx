import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { AuthContext } from "@/context/auth-context";
import { StudentContext } from "@/context/student-context";
import { fetchStudentBoughtCoursesService } from "@/services";
import { Watch } from "lucide-react";
import { useContext, useEffect } from "react";
import { useNavigate } from "react-router-dom";

function StudentCoursesPage() {
  const { auth } = useContext(AuthContext);
  const { studentBoughtCoursesList, setStudentBoughtCoursesList } =
    useContext(StudentContext);
  const navigate = useNavigate();

  async function fetchStudentBoughtCourses() {
    const response = await fetchStudentBoughtCoursesService(auth?.user?._id);
    if (response?.success) {
      setStudentBoughtCoursesList(response?.data);
    }
    console.log(response);
  }
  useEffect(() => {
    fetchStudentBoughtCourses();
  }, []);

  return (
    <div className="p-8 bg-gray-50 min-h-screen">
      <h1 className="text-4xl font-bold text-gray-900 mb-8">My Courses</h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {studentBoughtCoursesList && studentBoughtCoursesList.length > 0 ? (
          studentBoughtCoursesList.map((course) => (
            <Card
              key={course.id}
              className="flex flex-col rounded-xl overflow-hidden shadow-md border border-gray-300 bg-white transition-transform transform hover:scale-[1.02] hover:shadow-lg"
            >
              <CardContent className="p-5 flex-grow">
                {/* Course Image */}
                <div className="relative w-full h-44 rounded-lg overflow-hidden border border-gray-200">
                  <img
                    src={course?.courseImage}
                    alt={course?.title}
                    className="w-full h-full object-cover transition-transform duration-300 hover:scale-105"
                  />
                </div>

                {/* Course Title & Instructor */}
                <div className="mt-4">
                  <h3 className="text-lg font-semibold text-gray-900">
                    {course?.title}
                  </h3>
                  <p className="text-sm text-gray-700">
                    {course?.instructorName}
                  </p>
                </div>
              </CardContent>

              {/* Footer with Start Watching Button */}
              <CardFooter className="p-4 border-t border-gray-300 bg-gray-50">
                <Button
                  onClick={() =>
                    navigate(`/course-progress/${course?.courseId}`)
                  }
                  className="w-full flex items-center justify-center bg-blue-600 text-white hover:bg-blue-700 transition px-4 py-2 rounded-lg"
                >
                  <Watch className="mr-2 h-4 w-4" />
                  Start Watching
                </Button>
              </CardFooter>
            </Card>
          ))
        ) : (
          <div className="col-span-full flex flex-col items-center justify-center">
            <h1 className="text-3xl font-bold text-gray-800">
              No Courses Found
            </h1>
            <p className="text-gray-600 mt-2">
              You haven't enrolled in any courses yet.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default StudentCoursesPage;
