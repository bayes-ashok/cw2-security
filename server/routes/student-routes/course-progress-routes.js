const express = require("express");
const {
  getCurrentCourseProgress,
  markCurrentLectureAsViewed,
  resetCurrentCourseProgress,
} = require("../../controllers/student-controller/course-progress-controller");
const authenticateMiddleware = require("../../middleware/auth-middleware");

const router = express.Router();

router.get("/get/:userId/:courseId", authenticateMiddleware, getCurrentCourseProgress);
router.post("/mark-lecture-viewed", authenticateMiddleware, markCurrentLectureAsViewed);
router.post("/reset-progress", authenticateMiddleware, resetCurrentCourseProgress);
module.exports = router;
