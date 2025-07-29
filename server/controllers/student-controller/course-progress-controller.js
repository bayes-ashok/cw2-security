const { body, param, validationResult } = require('express-validator');
const CourseProgress = require("../../models/CourseProgress");
const Course = require("../../models/Course");
const StudentCourses = require("../../models/StudentCourses");
const sanitizeHtml = require('sanitize-html');
const logger = require("../../middleware/logger");

const markCurrentLectureAsViewed = [
  // Validation rules
  body('userId')
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('courseId')
    .notEmpty().withMessage('Course ID is required')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('lectureId')
    .notEmpty().withMessage('Lecture ID is required')
    .isMongoId().withMessage('Invalid lecture ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during marking lecture as viewed', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { userId, courseId, lectureId } = req.body;

      let progress = await CourseProgress.findOne({ userId, courseId });
      if (!progress) {
        progress = new CourseProgress({
          userId,
          courseId,
          lecturesProgress: [
            {
              lectureId,
              viewed: true,
              dateViewed: new Date(),
            },
          ],
        });
        await progress.save();
        logger.info('New course progress created', { userId, courseId, lectureId });
      } else {
        const lectureProgress = progress.lecturesProgress.find(
          (item) => item.lectureId.toString() === lectureId
        );

        if (lectureProgress) {
          lectureProgress.viewed = true;
          lectureProgress.dateViewed = new Date();
        } else {
          progress.lecturesProgress.push({
            lectureId,
            viewed: true,
            dateViewed: new Date(),
          });
        }
        await progress.save();
        logger.info('Lecture marked as viewed', { userId, courseId, lectureId });
      }

      const course = await Course.findById(courseId);
      if (!course) {
        logger.warn('Course not found during marking lecture', { courseId });
        return res.status(404).json({
          success: false,
          message: "Course not found",
        });
      }

      const allLecturesViewed =
        progress.lecturesProgress.length === course.curriculum.length &&
        progress.lecturesProgress.every((item) => item.viewed);

      if (allLecturesViewed) {
        progress.completed = true;
        progress.completionDate = new Date();
        await progress.save();
        logger.info('Course marked as completed', { userId, courseId });
      }

      res.status(200).json({
        success: true,
        message: "Lecture marked as viewed",
        data: progress,
      });
    } catch (error) {
      logger.error('Error marking lecture as viewed', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const getCurrentCourseProgress = [
  // Validation rules
  param('userId')
    .isMongoId().withMessage('Invalid user ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  param('courseId')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during course progress retrieval', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { userId, courseId } = req.params;

      const studentPurchasedCourses = await StudentCourses.findOne({ userId });
      const isCurrentCoursePurchasedByCurrentUserOrNot =
        studentPurchasedCourses?.courses?.findIndex(
          (item) => item.courseId.toString() === courseId
        ) > -1;

      if (!isCurrentCoursePurchasedByCurrentUserOrNot) {
        logger.warn('Course not purchased by user', { userId, courseId });
        return res.status(200).json({
          success: true,
          data: {
            isPurchased: false,
          },
          message: "You need to purchase this course to access it.",
        });
      }

      const currentUserCourseProgress = await CourseProgress.findOne({
        userId,
        courseId,
      });

      if (
        !currentUserCourseProgress ||
        currentUserCourseProgress?.lecturesProgress?.length === 0
      ) {
        const course = await Course.findById(courseId);
        if (!course) {
          logger.warn('Course not found during progress retrieval', { courseId });
          return res.status(404).json({
            success: false,
            message: "Course not found",
          });
        }

        logger.info('No progress found for course', { userId, courseId });
        return res.status(200).json({
          success: true,
          message: "No progress found, you can start watching the course",
          data: {
            courseDetails: course,
            progress: [],
            isPurchased: true,
          },
        });
      }

      const courseDetails = await Course.findById(courseId);
      logger.info('Course progress retrieved successfully', { userId, courseId });

      res.status(200).json({
        success: true,
        data: {
          courseDetails,
          progress: currentUserCourseProgress.lecturesProgress,
          completed: currentUserCourseProgress.completed,
          completionDate: currentUserCourseProgress.completionDate,
          isPurchased: true,
        },
      });
    } catch (error) {
      logger.error('Error retrieving course progress', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const resetCurrentCourseProgress = [
  // Validation rules
  body('userId')
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('courseId')
    .notEmpty().withMessage('Course ID is required')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during course progress reset', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { userId, courseId } = req.body;

      const progress = await CourseProgress.findOne({ userId, courseId });
      if (!progress) {
        logger.warn('Progress not found for reset', { userId, courseId });
        return res.status(404).json({
          success: false,
          message: "Progress not found",
        });
      }

      progress.lecturesProgress = [];
      progress.completed = false;
      progress.completionDate = null;
      await progress.save();

      logger.info('Course progress reset successfully', { userId, courseId });
      res.status(200).json({
        success: true,
        message: "Course progress has been reset",
        data: progress,
      });
    } catch (error) {
      logger.error('Error resetting course progress', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

module.exports = {
  markCurrentLectureAsViewed,
  getCurrentCourseProgress,
  resetCurrentCourseProgress,
};