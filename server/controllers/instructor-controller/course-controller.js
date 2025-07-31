const { body, param, validationResult } = require('express-validator');
const Course = require("../../models/Course");
const User = require("../../models/User");
const sanitizeHtml = require('sanitize-html');
const logger = require("../../middleware/logger");

const addNewCourse = [
  // Validation rules
  body('title')
    .trim()
    .notEmpty().withMessage('Course title is required')
    .isLength({ min: 3 }).withMessage('Course title must be at least 3 characters long')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('description')
    .optional()
    .trim()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: ['p', 'b', 'i', 'ul', 'li'], allowedAttributes: {} })),
  body('instructorId')
    .notEmpty().withMessage('Instructor ID is required')
    .isMongoId().withMessage('Invalid instructor ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('price')
    .optional()
    .isFloat({ min: 0 }).withMessage('Price must be a positive number')
    .customSanitizer((value) => sanitizeHtml(value.toString(), { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during course creation', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const courseData = req.body;
      const instructor = await User.findById(courseData.instructorId);
      if (!instructor) {
        logger.warn('Instructor not found during course creation', { instructorId: courseData.instructorId });
        return res.status(404).json({
          success: false,
          message: "Instructor not found",
        });
      }

      courseData.instructorName = sanitizeHtml(instructor.fName, { allowedTags: [], allowedAttributes: {} });
      const newlyCreatedCourse = new Course(courseData);
      const savedCourse = await newlyCreatedCourse.save();
      logger.info('Course created successfully', { courseId: savedCourse._id, title: savedCourse.title });

      res.status(201).json({
        success: true,
        message: "Course saved successfully",
        data: savedCourse,
      });
    } catch (error) {
      logger.error('Error during course creation', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const getAllCourses = async (req, res) => {
  try {
    const coursesList = await Course.find({});
    logger.info('Retrieved all courses', { count: coursesList.length });

    res.status(200).json({
      success: true,
      data: coursesList,
    });
  } catch (error) {
    logger.error('Error retrieving courses', { error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
};

const updateCourseByID = [
  // Validation rules
  param('id')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('title')
    .optional()
    .trim()
    .isLength({ min: 3 }).withMessage('Course title must be at least 3 characters long')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('description')
    .optional()
    .trim()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: ['p', 'b', 'i', 'ul', 'li'], allowedAttributes: {} })),
  body('instructorId')
    .optional()
    .isMongoId().withMessage('Invalid instructor ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('price')
    .optional()
    .isFloat({ min: 0 }).withMessage('Price must be a positive number')
    .customSanitizer((value) => sanitizeHtml(value.toString(), { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during course update', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { id } = req.params;
      const updatedCourseData = req.body;

      if (updatedCourseData.instructorId) {
        const instructor = await User.findById(updatedCourseData.instructorId);
        if (!instructor) {
          logger.warn('Instructor not found during course update', { instructorId: updatedCourseData.instructorId });
          return res.status(404).json({
            success: false,
            message: "Instructor not found",
          });
        }
        updatedCourseData.instructorName = sanitizeHtml(instructor.fName, { allowedTags: [], allowedAttributes: {} });
      }

      const updatedCourse = await Course.findByIdAndUpdate(
        id,
        updatedCourseData,
        { new: true, runValidators: true }
      );

      if (!updatedCourse) {
        logger.warn('Course not found during update', { courseId: id });
        return res.status(404).json({
          success: false,
          message: "Course not found",
        });
      }

      logger.info('Course updated successfully', { courseId: id, title: updatedCourse.title });
      res.status(200).json({
        success: true,
        message: "Course updated successfully",
        data: updatedCourse,
      });
    } catch (error) {
      logger.error('Error updating course', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const getCourseDetailsByID = [
  param('id')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during course retrieval', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { id } = req.params;
      const courseDetails = await Course.findById(id);

      if (!courseDetails) {
        logger.warn('Course not found during retrieval', { courseId: id });
        return res.status(404).json({
          success: false,
          message: "Course not found",
        });
      }

      logger.info('Course retrieved successfully', { courseId: id, title: courseDetails.title });
      res.status(200).json({
        success: true,
        data: courseDetails,
      });
    } catch (error) {
      logger.error('Error retrieving course details', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const deleteCourseByID = [
  param('id')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during course deletion', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { id } = req.params;
      const deletedCourse = await Course.findByIdAndDelete(id);

      if (!deletedCourse) {
        logger.warn('Course not found during deletion', { courseId: id });
        return res.status(404).json({
          success: false,
          message: "Course not found",
        });
      }

      logger.info('Course deleted successfully', { courseId: id, title: deletedCourse.title });
      res.status(200).json({
        success: true,
        message: "Course deleted successfully",
        data: deletedCourse,
      });
    } catch (error) {
      logger.error('Error deleting course', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

module.exports = {
  addNewCourse,
  getAllCourses,
  updateCourseByID,
  getCourseDetailsByID,
  deleteCourseByID,
};