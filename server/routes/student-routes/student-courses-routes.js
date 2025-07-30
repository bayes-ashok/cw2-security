const express = require("express");
const {
  getCoursesByStudentId,
  enrollStudentInCourse
} = require("../../controllers/student-controller/student-courses-controller");
const authenticateMiddleware = require("../../middleware/auth-middleware");

const router = express.Router();

router.get("/get/", authenticateMiddleware, getCoursesByStudentId);
router.post("/enroll", authenticateMiddleware, enrollStudentInCourse);

module.exports = router;
