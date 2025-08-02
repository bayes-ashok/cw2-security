const { query, param, validationResult } = require('express-validator');
const Course = require("../../models/Course");
const StudentCourses = require("../../models/StudentCourses");
const sanitizeHtml = require('sanitize-html');
const logger = require("../../middleware/logger");

const getAllStudentViewCourses = [
  // Validation rules
  query('category')
    .optional()
    .trim()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  query('level')
    .optional()
    .trim()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  query('primaryLanguage')
    .optional()
    .trim()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  query('sortBy')
    .optional()
    .isIn(['price-lowtohigh', 'price-hightolow', 'title-atoz', 'title-ztoa'])
    .withMessage('Invalid sortBy value')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during student view courses retrieval', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { category, level, primaryLanguage, sortBy = "price-lowtohigh" } = req.query;

      let filters = {};
      if (category?.length) {
        filters.category = { $in: category.split(",") };
      }
      if (level?.length) {
        filters.level = { $in: level.split(",") };
      }
      if (primaryLanguage?.length) {
        filters.primaryLanguage = { $in: primaryLanguage.split(",") };
      }

      let sortParam = {};
      switch (sortBy) {
        case "price-lowtohigh":
          sortParam.pricing = 1;
          break;
        case "price-hightolow":
          sortParam.pricing = -1;
          break;
        case "title-atoz":
          sortParam.title = 1;
          break;
        case "title-ztoa":
          sortParam.title = -1;
          break;
        default:
          sortParam.pricing = 1;
          break;
      }

      const coursesList = await Course.find(filters).sort(sortParam);
      logger.info('Retrieved student view courses', { count: coursesList.length, filters, sortBy });

      res.status(200).json({
        success: true,
        data: coursesList,
      });
    } catch (error) {
      logger.error('Error retrieving student view courses', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const getAllCourseTitles = async (req, res) => {
  try {
    const coursesList = await Course.find({}, 'title image category');
    logger.info('Retrieved all course titles', { count: coursesList.length });

    res.status(200).json({
      success: true,
      data: coursesList,
    });
  } catch (error) {
    logger.error('Error retrieving course titles', { error: error.message });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
};


const getStudentViewCourseDetails = [
  // Validation rules
  param('id')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during course details retrieval', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { id } = req.params;
      const courseDetails = await Course.findById(id);

      if (!courseDetails) {
        logger.warn('Course not found during details retrieval', { courseId: id });
        return res.status(404).json({
          success: false,
          message: "No course details found",
          data: null,
        });
      }

      // Filter curriculum to include only freePreview: true videos
      const sanitizedCourseDetails = {
        ...courseDetails._doc,
        curriculum: courseDetails.curriculum.filter(lecture => lecture.freePreview === true)
      };

      logger.info('Course details retrieved successfully', { courseId: id, title: courseDetails.title });

      res.status(200).json({
        success: true,
        data: sanitizedCourseDetails,
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

const checkCoursePurchaseInfo = [
  // Validation rules
  param('id')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  param('studentId')
    .isMongoId().withMessage('Invalid student ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during course purchase check', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { id, studentId } = req.params;
      const studentCourses = await StudentCourses.findOne({ userId: studentId });

      const ifStudentAlreadyBoughtCurrentCourse =
        studentCourses?.courses.some((item) => item.courseId.toString() === id) || false;

      if (!studentCourses) {
        logger.warn('Student course record not found', { studentId, courseId: id });
      } else {
        logger.info('Checked course purchase status', { studentId, courseId: id, purchased: ifStudentAlreadyBoughtCurrentCourse });
      }

      res.status(200).json({
        success: true,
        data: ifStudentAlreadyBoughtCurrentCourse,
      });
    } catch (error) {
      logger.error('Error checking course purchase info', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

module.exports = {
  getAllStudentViewCourses,
  getStudentViewCourseDetails,
  checkCoursePurchaseInfo,
  getAllCourseTitles
};