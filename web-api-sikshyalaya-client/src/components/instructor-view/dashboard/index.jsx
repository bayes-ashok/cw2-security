import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DollarSign, Users } from "lucide-react";

function InstructorDashboard({ listOfCourses }) {
  function calculateTotalStudentsAndProfit() {
    const { totalStudents, totalProfit, studentList } = listOfCourses.reduce(
      (acc, course) => {
        const studentCount = course.students.length;
        acc.totalStudents += studentCount;
        acc.totalProfit += course.pricing * studentCount;

        course.students.forEach((student) => {
          acc.studentList.push({
            courseTitle: course.title,
            studentName: student.studentName,
            studentEmail: student.studentEmail,
          });
        });

        return acc;
      },
      {
        totalStudents: 0,
        totalProfit: 0,
        studentList: [],
      }
    );

    return {
      totalProfit,
      totalStudents,
      studentList,
    };
  }

  const config = [
    {
      label: "Total Students",
      value: calculateTotalStudentsAndProfit().totalStudents,
    },
    {
      label: "Total Revenue",
      value: `Rs. ${calculateTotalStudentsAndProfit().totalProfit}`,
    },
  ];

  return (
    <div className="">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        {config.map((item, index) => (
          <Card key={index} className="bg-white shadow-lg p-6 rounded-xl">
            <CardHeader className="flex flex-row items-center justify-between pb-4">
              <CardTitle className="text-xl font-semibold text-gray-900">
                {item.label}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-gray-900">
                {item.label === "Total Revenue(in Rs.)"
                  ? `Rs. ${calculateTotalStudentsAndProfit().totalProfit}`
                  : item.value}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Students List Table */}
      <Card className="bg-white shadow-lg p-6 rounded-xl">
        <CardHeader>
          <CardTitle className="text-gray-900 text-2xl font-bold">
            Students List
          </CardTitle>
        </CardHeader>
        <CardContent className="p-4 bg-white rounded-lg">
          <div className="overflow-x-auto">
            <Table className="w-full border border-gray-300 rounded-lg">
              <TableHeader className="bg-gray-100 text-gray-900">
                <TableRow>
                  <TableHead className="p-4 text-left font-bold">
                    Course Name
                  </TableHead>
                  <TableHead className="p-4 text-left font-bold">
                    Student Name
                  </TableHead>
                  <TableHead className="p-4 text-left font-bold">
                    Student Email
                  </TableHead>
                </TableRow>
              </TableHeader>

              <TableBody>
                {calculateTotalStudentsAndProfit().studentList.length > 0 ? (
                  calculateTotalStudentsAndProfit().studentList.map(
                    (studentItem, index) => (
                      <TableRow
                        key={index}
                        className={`border-b border-gray-300 ${
                          index % 2 === 0 ? "bg-gray-50" : "bg-gray-100"
                        } hover:bg-gray-200 transition duration-300`}
                      >
                        <TableCell className="p-4 text-gray-900">
                          {studentItem.courseTitle}
                        </TableCell>
                        <TableCell className="p-4 text-gray-900">
                          {studentItem.studentName}
                        </TableCell>
                        <TableCell className="p-4 text-gray-900">
                          {studentItem.studentEmail}
                        </TableCell>
                      </TableRow>
                    )
                  )
                ) : (
                  <TableRow className="bg-gray-100">
                    <TableCell
                      colSpan="3"
                      className="p-4 text-center text-gray-400"
                    >
                      No students enrolled yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default InstructorDashboard;
