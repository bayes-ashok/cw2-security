const express = require("express");
const {
  getStudentViewCourseDetails,
  getAllStudentViewCourses,
  checkCoursePurchaseInfo,
  getAllCourseTitles
} = require("../../controllers/student-controller/course-controller");
const authenticateMiddleware = require("../../middleware/auth-middleware");
const router = express.Router();

router.get("/get", authenticateMiddleware, getAllStudentViewCourses);
router.get("/getAllCourseTitles", authenticateMiddleware, getAllCourseTitles);
router.get("/get/details/:id",authenticateMiddleware, getStudentViewCourseDetails);
router.get("/purchase-info/:id/:studentId", authenticateMiddleware, checkCoursePurchaseInfo);

module.exports = router;
