const express = require("express");
const {
  getCoursesByStudentId,
  enrollStudentInCourse
} = require("../../controllers/student-controller/student-courses-controller");

const router = express.Router();

router.get("/get/:studentId", getCoursesByStudentId);
router.post("/enroll", enrollStudentInCourse);

module.exports = router;
