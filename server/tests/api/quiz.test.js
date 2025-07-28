const request = require("supertest");
const mongoose = require("mongoose");
const { app } = require("../../server");
const QuizSet = require("../../models/Quiz");

let chai;
let expect;
let quizSetId;

before(async () => {
  chai = await import("chai");
  expect = chai.expect;
});

describe("📝 Quiz API Tests", () => {
  before(async () => {
    if (mongoose.connection.readyState === 0) {
      const uri = process.env.TEST_DB_URI || "mongodb://localhost:27017/testdb";
      await mongoose.connect(uri);
    }

    // ✅ Clear previous test data
    await QuizSet.deleteMany();
  });

  after(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
  });

  it("✅ Should create a new quiz set (POST /create)", async () => {
    const quizData = {
      title: "JavaScript Basics",
      category: "Programming",
      description: "Basic quiz on JavaScript fundamentals",
    };

    const res = await request(app)
      .post("/instructor/quiz/create") // Ensure correct route
      .send(quizData);

    console.log("🚀 Quiz Create API Response:", res.status, res.body);

    expect(res.status).to.equal(201);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body).to.have.property("data");
    expect(res.body.data).to.have.property("title").that.equals(quizData.title);

    quizSetId = res.body.data?._id; // Store quizSetId for later tests
  });

  it("✅ Should get all quiz sets (GET /)", async () => {
    const res = await request(app).get("/instructor/quiz/");

    console.log("🚀 Get All Quiz Sets API Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body).to.have.property("data").that.is.an("array");
    expect(res.body.data.length).to.be.greaterThan(0);
  });

  it("✅ Should get quiz sets by category (GET /category/:category)", async () => {
    const res = await request(app).get(`/instructor/quiz/category/Programming`);

    console.log("🚀 Get Quiz By Category API Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body).to.have.property("data").that.is.an("array");
    expect(res.body.data.length).to.be.greaterThan(0);
    expect(res.body.data[0]).to.have.property("category").that.equals("Programming");
  });

  it("✅ Should delete a quiz set (DELETE /delete/:id)", async () => {
    if (!quizSetId) {
      console.log("⚠️ No valid quiz set ID, skipping this test.");
      return;
    }

    const res = await request(app).delete(`/instructor/quiz/delete/${quizSetId}`);

    console.log("🚀 Delete Quiz Set API Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("message").that.includes("Deleted");

    // Ensure quiz set is actually deleted
    const checkQuiz = await QuizSet.findById(quizSetId);
    expect(checkQuiz).to.be.null;
  });

  it("❌ Should return 404 when deleting a non-existent quiz set", async () => {
    const res = await request(app).delete(`/instructor/quiz/delete/${new mongoose.Types.ObjectId()}`);

    console.log("🚀 Delete Non-Existent Quiz Set API Response:", res.status, res.body);

    expect(res.status).to.equal(404);
    expect(res.body).to.have.property("message").that.includes("Quiz Set not found");
  });
});
