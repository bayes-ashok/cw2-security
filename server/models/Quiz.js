const mongoose = require("mongoose");

const quizSetSchema = new mongoose.Schema({
  title: { type: String, required: true },
  category: { type: String, required: true },
  description: String,
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("QuizSet", quizSetSchema);
