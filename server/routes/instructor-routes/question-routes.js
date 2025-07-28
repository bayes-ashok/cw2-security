const express = require("express");
const { addQuestion, getQuestionsByQuizSet } = require("../../controllers/instructor-controller/question-controller");

const router = express.Router();

router.post("/add", addQuestion);
router.get("/:quizSetId", getQuestionsByQuizSet);

module.exports = router;
