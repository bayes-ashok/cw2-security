const QuizSet = require("../../models/Quiz");

// Create a new quiz set
const createQuizSet = async (req, res) => {
  try {
    const newQuizSet = new QuizSet(req.body);
    await newQuizSet.save();
    res.status(201).json({ success: true, data: newQuizSet });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error creating quiz set" });
  }
};

// Fetch all quiz sets
const getAllQuizSets = async (req, res) => {
  try {
    const quizSets = await QuizSet.find();
    res.json({ success: true, data: quizSets });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error fetching quiz sets" });
  }
};

// Get quiz sets by category
const getQuizSetsByCategory = async (req, res) => {
  try {
    const { category } = req.params;
    const quizSets = await QuizSet.find({ category });
    res.json({ success: true, data: quizSets });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error fetching quiz sets by category" });
  }
};


// Delete a quiz set by ID and remove associated questions
const deleteQuizSet = async (req, res) => {
  try {
    const { id } = req.params;

    // Find and delete the quiz set
    const deletedQuizSet = await QuizSet.findByIdAndDelete(id);
    if (!deletedQuizSet) {
      return res.status(404).json({ message: "Quiz Set not found" });
    } else{
      return res.status(200).json({ message: "Deleted" });

    }

  } catch (error) {
    console.error("Error deleting quiz set:", error);
    res.status(500).json({ message: "Error deleting quiz set", error });
  }
};



module.exports = { createQuizSet, getAllQuizSets, getQuizSetsByCategory,deleteQuizSet };
