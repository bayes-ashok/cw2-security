const express = require("express");
const {
  addNewCourse,
  getAllCourses,
  getCourseDetailsByID,
  updateCourseByID,
  deleteCourseByID
} = require("../../controllers/instructor-controller/course-controller");
const authenticateAdmin = require("../../middleware/admin-auth-middleware");
const router = express.Router();

router.post("/add", authenticateAdmin, addNewCourse);
router.get("/get", authenticateAdmin, getAllCourses);
router.get("/get/details/:id",authenticateAdmin, getCourseDetailsByID);
router.put("/update/:id", authenticateAdmin, updateCourseByID);
router.delete("/delete/:id", authenticateAdmin, deleteCourseByID);

module.exports = router;
