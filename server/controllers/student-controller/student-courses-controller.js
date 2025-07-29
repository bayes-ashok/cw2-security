const StudentCourses = require("../../models/StudentCourses");
const Course = require("../../models/Course");
const User = require("../../models/User");
const getCoursesByStudentId = async (req, res) => {
  try {
    const studentId  = req.user.id;
    const studentBoughtCourses = await StudentCourses.findOne({ userId: studentId });

    if (!studentBoughtCourses) {
      return res.status(404).json({
        success: false,
        message: "No courses found for this student",
      });
    }

    res.status(200).json({
      success: true,
      data: studentBoughtCourses.courses || [],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Some error occurred!",
    });
  }
};


const enrollStudentInCourse = async (req, res) => {
  try {
    const { studentId, courseId } = req.body;

    if (!studentId || !courseId) {
      return res.status(400).json({ message: "Student ID and Course ID are required." });
    }

    // Fetch student details from User model
    const student = await User.findById(studentId);
    if (!student) {
      return res.status(404).json({ message: "Student not found." });
    }

    // Fetch course details
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ message: "Course not found." });
    }

    // Define course details for the student record
    const courseDetails = {
      courseId,
      title: course.title,
      instructorId: course.instructorId,
      instructorName: course.instructorName,
      dateOfPurchase: new Date(),
      courseImage: course.image,
    };

    // Check if the student already has a record in StudentCourses
    let studentCourses = await StudentCourses.findOne({ userId: studentId });

    if (studentCourses) {
      // Check if the course is already added
      const courseExists = studentCourses.courses.some((c) => c.courseId === courseId);
      if (!courseExists) {
        studentCourses.courses.push(courseDetails);
        await studentCourses.save();
      }
    } else {
      // If studentCourses record does not exist, create a new one
      studentCourses = new StudentCourses({
        userId: studentId,
        courses: [courseDetails],
      });
      await studentCourses.save();
    }

    console.log("Student course record updated successfully!");

    // Check if the student is already enrolled in the course
    const studentExistsInCourse = course.students.some((s) => s.studentId === studentId);

    if (!studentExistsInCourse) {
      course.students.push({
        studentId,
        studentName: student.fName, // Fetching name from User model
        studentEmail: student.email, // Fetching email from User model
        paidAmount: course.pricing ? course.pricing.toString() : "0",
      });

      await course.save();
      console.log("Student added to the course successfully!");
    } else {
      console.log("Student already enrolled in the course.");
    }

    return res.status(200).json({ message: "Student successfully enrolled in the course." });

  } catch (error) {
    console.error("Error enrolling student:", error);
    return res.status(500).json({ message: "Error enrolling student in course." });
  }
};


module.exports = { getCoursesByStudentId,enrollStudentInCourse };
