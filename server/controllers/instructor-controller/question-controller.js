const Question = require("../../models/Question");

// Add a question to a quiz set
const addQuestion = async (req, res) => {
    try {
        const { quizSetId, questions } = req.body;
    
        if (!quizSetId || !questions || !Array.isArray(questions)) {
          return res.status(400).json({ success: false, message: "Invalid input data" });
        }
    
        const newQuestions = questions.map((q) => ({
          quizSetId,
          question: q.question,
          options: q.options,
          correctAnswer: q.correctAnswer,
        }));
    
        const savedQuestions = await Question.insertMany(newQuestions);
    
        res.status(201).json({ success: true, data: savedQuestions });
      } catch (err) {
        res.status(500).json({ success: false, message: "Error adding questions" });
      }
};

// Get questions for a specific quiz set
const getQuestionsByQuizSet = async (req, res) => {
    try {
        const { quizSetId } = req.params;
        const questions = await Question.find({ quizSetId });
        res.json({ success: true, data: questions });
      } catch (err) {
        res.status(500).json({ success: false, message: "Error fetching questions" });
      }
};

module.exports = { addQuestion, getQuestionsByQuizSet };
