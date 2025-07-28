const mongoose = require("mongoose");

const questionSchema = new mongoose.Schema({
  quizSetId: { type: mongoose.Schema.Types.ObjectId, ref: "QuizSet", required: true },
  question: { type: String, required: true },
  options: [{ type: String, required: true }],
  correctAnswer: { type: Number, required: true },
});

module.exports = mongoose.model("Question", questionSchema);
