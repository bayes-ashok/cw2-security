const express = require("express");
const { createQuizSet, getAllQuizSets, getQuizSetsByCategory,deleteQuizSet } = require("../../controllers/instructor-controller/quiz-controller");

const router = express.Router();

router.post("/create", createQuizSet);
router.get("/", getAllQuizSets);
router.get("/category/:category", getQuizSetsByCategory);
router.delete("/delete/:id", deleteQuizSet);

module.exports = router;
