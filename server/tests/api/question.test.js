const request = require("supertest");
const mongoose = require("mongoose");
const { app } = require("../../server");
const Question = require("../../models/Question");
const QuizSet = require("../../models/Quiz");

let chai;
let expect;
let quizSetId;
let questionId;

before(async () => {
  chai = await import("chai");
  expect = chai.expect;
});

describe("❓ Question API Tests", () => {
  before(async () => {
    if (mongoose.connection.readyState === 0) {
      const uri = process.env.TEST_DB_URI || "mongodb://localhost:27017/testdb";
      await mongoose.connect(uri);
    }

    // ✅ Clear previous test data
    await Question.deleteMany();
    await QuizSet.deleteMany();

    // ✅ Create a Quiz Set for testing questions
    const quizSet = new QuizSet({
      title: "React Basics",
      category: "Programming",
      description: "A basic quiz on React.js",
    });

    const savedQuizSet = await quizSet.save();
    quizSetId = savedQuizSet._id;
  });

  after(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
  });

  it("✅ Should add new questions to a quiz set (POST /add)", async () => {
    const questionData = {
      quizSetId,
      questions: [
        {
          question: "What is React?",
          options: ["Library", "Framework", "Language", "Database"],
          correctAnswer: 0,
        },
        {
          question: "Which hook is used for state management?",
          options: ["useEffect", "useContext", "useState", "useReducer"],
          correctAnswer: 2,
        },
      ],
    };

    const res = await request(app).post("/instructor/question/add").send(questionData);

    console.log("🚀 Add Question API Response:", res.status, res.body);

    expect(res.status).to.equal(201);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body).to.have.property("data").that.is.an("array");
    expect(res.body.data.length).to.equal(2);

    questionId = res.body.data[0]._id; // Store the question ID for later tests
  });

  it("✅ Should get all questions for a specific quiz set (GET /:quizSetId)", async () => {
    const res = await request(app).get(`/instructor/question/${quizSetId}`);

    console.log("🚀 Get Questions API Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body).to.have.property("data").that.is.an("array");
    expect(res.body.data.length).to.be.greaterThan(0);
  });

  it("❌ Should return an empty array for a non-existent quiz set (GET /:quizSetId)", async () => {
    const fakeQuizSetId = new mongoose.Types.ObjectId();
    const res = await request(app).get(`/instructor/question/${fakeQuizSetId}`);

    console.log("🚀 Get Questions for Non-Existent QuizSet API Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body.data).to.be.an("array").that.is.empty;
  });
});
