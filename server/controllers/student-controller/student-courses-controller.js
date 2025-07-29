const { body, validationResult } = require('express-validator');
const StudentCourses = require("../../models/StudentCourses");
const Course = require("../../models/Course");
const User = require("../../models/User");
const sanitizeHtml = require('sanitize-html');
const logger = require("../../middleware/logger");

const getCoursesByStudentId = [
  // Controller logic
  async (req, res) => {
    try {
      const studentId = req.user?.id;
      if (!studentId) {
        logger.warn('No student ID provided in request');
        return res.status(401).json({
          success: false,
          message: "Unauthorized: Student ID is required",
        });
      }

      const sanitizedStudentId = sanitizeHtml(studentId, { allowedTags: [], allowedAttributes: {} });
      const studentBoughtCourses = await StudentCourses.findOne({ userId: sanitizedStudentId });

      if (!studentBoughtCourses) {
        logger.warn('No courses found for student', { studentId: sanitizedStudentId });
        return res.status(404).json({
          success: false,
          message: "No courses found for this student",
        });
      }

      logger.info('Retrieved courses for student', { studentId: sanitizedStudentId, courseCount: studentBoughtCourses.courses.length });
      res.status(200).json({
        success: true,
        data: studentBoughtCourses.courses || [],
      });
    } catch (error) {
      logger.error('Error retrieving student courses', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const enrollStudentInCourse = [
  // Validation rules
  body('studentId')
    .notEmpty().withMessage('Student ID is required')
    .isMongoId().withMessage('Invalid student ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('courseId')
    .notEmpty().withMessage('Course ID is required')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during student enrollment', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { studentId, courseId } = req.body;

      const student = await User.findById(studentId);
      if (!student) {
        logger.warn('Student not found during enrollment', { studentId });
        return res.status(404).json({ success: false, message: "Student not found" });
      }

      const course = await Course.findById(courseId);
      if (!course) {
        logger.warn('Course not found during enrollment', { courseId });
        return res.status(404).json({ success: false, message: "Course not found" });
      }

      const courseDetails = {
        courseId,
        title: sanitizeHtml(course.title, { allowedTags: [], allowedAttributes: {} }),
        instructorId: course.instructorId,
        instructorName: sanitizeHtml(course.instructorName, { allowedTags: [], allowedAttributes: {} }),
        dateOfPurchase: new Date(),
        courseImage: course.image ? sanitizeHtml(course.image, { allowedTags: [], allowedAttributes: {} }) : null,
      };

      let studentCourses = await StudentCourses.findOne({ userId: studentId });
      if (studentCourses) {
        const courseExists = studentCourses.courses.some((c) => c.courseId.toString() === courseId);
        if (!courseExists) {
          studentCourses.courses.push(courseDetails);
          await studentCourses.save();
          logger.info('Course added to existing student courses', { studentId, courseId });
        } else {
          logger.info('Student already enrolled in course', { studentId, courseId });
        }
      } else {
        studentCourses = new StudentCourses({
          userId: studentId,
          courses: [courseDetails],
        });
        await studentCourses.save();
        logger.info('New student courses record created', { studentId, courseId });
      }

      const studentExistsInCourse = course.students.some((s) => s.studentId.toString() === studentId);
      if (!studentExistsInCourse) {
        course.students.push({
          studentId,
          studentName: sanitizeHtml(student.fName, { allowedTags: [], allowedAttributes: {} }),
          studentEmail: sanitizeHtml(student.email, { allowedTags: [], allowedAttributes: {} }),
          paidAmount: course.pricing ? course.pricing.toString() : "0",
        });
        await course.save();
        logger.info('Student added to course', { studentId, courseId });
      } else {
        logger.info('Student already enrolled in course', { studentId, courseId });
      }

      res.status(200).json({
        success: true,
        message: "Student successfully enrolled in the course",
      });
    } catch (error) {
      logger.error('Error enrolling student in course', { error: error.message });
      return res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

module.exports = { getCoursesByStudentId, enrollStudentInCourse };