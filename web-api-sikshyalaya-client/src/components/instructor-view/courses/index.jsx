import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  courseCurriculumInitialFormData,
  courseLandingInitialFormData,
} from "@/config";
import { InstructorContext } from "@/context/instructor-context";
import { Edit, Trash } from "lucide-react";
import { useContext } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

function InstructorCourses({ listOfCourses, setListOfCourses }) {
  const navigate = useNavigate();
  const {
    setCurrentEditedCourseId,
    setCourseLandingFormData,
    setCourseCurriculumFormData,
  } = useContext(InstructorContext);

  // Handle delete course
  const handleDeleteCourse = async (courseId) => {
    try {
      const response = await fetch(
        `http://localhost:8000/instructor/course/delete/${courseId}`,
        {
          method: "DELETE",
        }
      );

      const result = await response.json();

      if (result.success) {
        toast.success("Course deleted successfully!");
        setTimeout(() => {
          window.location.reload(); 
        }, 1000);
      } else {
        toast.error(result.message || "Failed to delete course.");
      }
    } catch (error) {
      console.error("Error deleting course:", error);
    }
  };

  return (
    <Card className="bg-white shadow-lg p-4 rounded-xl">
      <CardHeader className="flex justify-between items-center pb-2">
        <div className="flex justify-end w-full">
          <Button
            onClick={() => {
              setCurrentEditedCourseId(null);
              setCourseLandingFormData(courseLandingInitialFormData);
              setCourseCurriculumFormData(courseCurriculumInitialFormData);
              navigate("/instructor/create-new-course");
            }}
            className="bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg px-6 py-3 transition duration-300"
          >
            Create New Course
          </Button>
        </div>
      </CardHeader>
      <CardContent className="bg-white p-4 rounded-lg">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="bg-white text-gray-900">
                <TableHead className="p-3">Course</TableHead>
                <TableHead className="p-3">Students</TableHead>
                <TableHead className="p-3">Revenue</TableHead>
                <TableHead className="p-3">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {listOfCourses && listOfCourses.length > 0 ? (
                listOfCourses.map((course, index) => (
                  <TableRow
                    key={course._id}
                    className={`border-b border-gray-200 ${
                      index % 2 === 0 ? "bg-gray-50" : "bg-gray-100"
                    } hover:bg-gray-200 transition`}
                  >
                    <TableCell className="p-3 font-medium text-gray-900">
                      {course?.title}
                    </TableCell>
                    <TableCell className="p-3 text-gray-900">
                      {course?.students?.length}
                    </TableCell>
                    <TableCell className="p-3 text-gray-900">
                      Rs. {course?.students?.length * course?.pricing}
                    </TableCell>
                    <TableCell className="p-3 text-right flex gap-2">
                      <Button
                        onClick={() => {
                          navigate(`/instructor/edit-course/${course?._id}`);
                        }}
                        className="bg-yellow-500 hover:bg-yellow-600 text-white p-2 rounded-md"
                      >
                        <Edit className="h-5 w-5" />
                      </Button>
                      <Button
                        onClick={() => handleDeleteCourse(course._id)}
                        className="bg-red-500 hover:bg-red-600 text-white p-2 rounded-md"
                      >
                        <Trash className="h-5 w-5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow className="bg-gray-50">
                  <TableCell
                    colSpan="4"
                    className="p-4 text-center text-gray-400"
                  >
                    No courses found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

export default InstructorCourses;
