const Course = require("../../models/Course");
const User = require("../../models/User"); // Make sure to import the User model

const addNewCourse = async (req, res) => {
  try {
    const courseData = req.body;
    
    // Find the instructor using the provided instructorId
    const instructor = await User.findById(courseData.instructorId);
    if (instructor) {
      // Set the instructorName to the user's fName
      courseData.instructorName = instructor.fName;
    } else {
      // Optionally handle the case where the instructor is not found
      return res.status(404).json({
        success: false,
        message: "Instructor not found",
      });
    }

    const newlyCreatedCourse = new Course(courseData);
    const savedCourse = await newlyCreatedCourse.save();

    res.status(201).json({
      success: true,
      message: "Course saved successfully",
      data: savedCourse,
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({
      success: false,
      message: "Some error occurred!",
    });
  }
};
const getAllCourses = async (req, res) => {
    try {
      const coursesList = await Course.find({});
  
      res.status(200).json({
        success: true,
        data: coursesList,
      });
    } catch (e) {
      console.log(e);
      res.status(500).json({
        success: false,
        message: "Some error occured!",
      });
    }
  };
  

  const updateCourseByID = async (req, res) => {
    try {
      const { id } = req.params;
      const updatedCourseData = req.body;
  
      // If an instructorId is provided, update the instructorName
      if (updatedCourseData.instructorId) {
        const instructor = await User.findById(updatedCourseData.instructorId);
        if (instructor) {
          updatedCourseData.instructorName = instructor.fName;
        } else {
          return res.status(404).json({
            success: false,
            message: "Instructor not found",
          });
        }
      }
  
      const updatedCourse = await Course.findByIdAndUpdate(
        id,
        updatedCourseData,
        { new: true }
      );
  
      if (!updatedCourse) {
        return res.status(404).json({
          success: false,
          message: "Course not found!",
        });
      }
  
      res.status(200).json({
        success: true,
        message: "Course updated successfully",
        data: updatedCourse,
      });
    } catch (e) {
      console.log(e);
      res.status(500).json({
        success: false,
        message: "Some error occurred!",
      });
    }
  };
  
  const getCourseDetailsByID = async (req, res) => {
    try {
      const { id } = req.params;
      const courseDetails = await Course.findById(id);
  
      if (!courseDetails) {
        return res.status(404).json({
          success: false,
          message: "Course not found!",
        });
      }
  
      res.status(200).json({
        success: true,
        data: courseDetails,
      });
    } catch (e) {
      console.log(e);
      res.status(500).json({
        success: false,
        message: "Some error occured!",
      });
    }
  };

  const deleteCourseByID = async (req, res) => {
    try {
      const { id } = req.params;
      const deletedCourse = await Course.findByIdAndDelete(id);
  
      if (!deletedCourse) {
        return res.status(404).json({
          success: false,
          message: "Course not found!",
        });
      }
  
      res.status(200).json({
        success: true,
        message: "Course deleted successfully",
        data: deletedCourse,
      });
    } catch (e) {
      console.log(e);
      res.status(500).json({
        success: false,
        message: "Some error occurred!",
      });
    }
  };
  
module.exports = {
  addNewCourse,
  getAllCourses,
  updateCourseByID,
  getCourseDetailsByID,
  deleteCourseByID,
};
