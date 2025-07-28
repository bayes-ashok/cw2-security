const request = require("supertest");
const mongoose = require("mongoose");
const { app } = require("../../server");
const User = require("../../models/User");
const Course = require("../../models/Course");
const bcrypt = require("bcryptjs");

let chai;
let expect;
let instructorId;
let courseId;
let token;

before(async () => {
  chai = await import("chai");
  expect = chai.expect;
});

describe("📚 Course API Tests", () => {
  before(async () => {
    if (mongoose.connection.readyState === 0) {
      const uri = process.env.TEST_DB_URI || "mongodb://localhost:27017/testdb";
      await mongoose.connect(uri);
    }

    // Clear previous test data
    await User.deleteMany();
    await Course.deleteMany();

    // ✅ Create a test instructor
    const instructor = new User({
      fName: "Instructor User",
      email: "instructor@example.com",
      password: await bcrypt.hash("InstructorPass123", 10),
      role: "instructor",
      verified: true, // Mark as verified
    });

    await instructor.save();
    instructorId = instructor._id; // Store valid instructor ObjectId

    // ✅ Instructor Login to Get Token
    const res = await request(app).post("/auth/login").send({
      email: "instructor@example.com",
      password: "InstructorPass123",
    });

    console.log("🚀 Instructor Login Response:", res.body);
    token = res.body.data?.accessToken; // Store token for authentication
  });

  after(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
  });

  it("✅ Should create a new course (POST /instructor/course/add)", async () => {
    const res = await request(app)
      .post("/instructor/course/add")
      .set("Authorization", `Bearer ${token}`)
      .send({
        instructorId: instructorId.toString(), // Convert to string for MongoDB ObjectId
        instructorName: "Instructor User",
        title: "MERN Stack Development",
        category: "Web Development",
        level: "Beginner",
        primaryLanguage: "English",
        subtitle: "Learn MERN Stack",
        description: "This course covers the MERN stack in-depth.",
        pricing: 49.99,
        isPublished: true,
      });

    console.log("🚀 Course Create API Response:", res.status, res.body);

    expect(res.status).to.equal(201);
    expect(res.body).to.have.property("message").that.includes("Course saved successfully"); // ✅ Adjusted message
    expect(res.body).to.have.property("data");

    courseId = res.body.data?._id; // ✅ Store courseId for later tests
  });

  it("✅ Should get all courses (GET /instructor/course/get)", async () => {
    const res = await request(app)
      .get("/instructor/course/get")
      .set("Authorization", `Bearer ${token}`);

    console.log("🚀 Get Courses API Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("success").that.is.true; // ✅ Updated check
    expect(res.body.data).to.be.an("array");
    expect(res.body.data.length).to.be.greaterThan(0);
  });

  it("✅ Should get course details by ID (GET /instructor/course/get/details/:id)", async () => {
    if (!courseId) {
      console.log("⚠️ No valid course ID, skipping this test.");
      return;
    }

    const res = await request(app)
      .get(`/instructor/course/get/details/${courseId}`)
      .set("Authorization", `Bearer ${token}`);

    console.log("🚀 Get Course Details Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body).to.have.property("data");
    expect(res.body.data).to.have.property("title").that.includes("MERN Stack Development");
  });

  it("✅ Should get course details for students (GET /student/course/get/details/:id)", async () => {
    if (!courseId) {
      console.log("⚠️ No valid course ID, skipping this test.");
      return;
    }

    const res = await request(app)
      .get(`/student/course/get/details/${courseId}`);

    console.log("🚀 Get Student Course Details Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body).to.have.property("data");
    expect(res.body.data).to.have.property("title").that.includes("MERN Stack Development");
  });



  it("✅ Should get all student courses (GET /student/course/get)", async () => {
    const res = await request(app)
      .get("/student/course/get");

    console.log("🚀 Get Student Courses API Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body.data).to.be.an("array");
    expect(res.body.data.length).to.be.greaterThan(0);
  });

  it("✅ Should delete a course (DELETE /instructor/course/delete/:id)", async () => {
    if (!courseId) {
      console.log("⚠️ No valid course ID, skipping this test.");
      return;
    }

    const res = await request(app)
      .delete(`/instructor/course/delete/${courseId}`)
      .set("Authorization", `Bearer ${token}`);

    console.log("🚀 Delete Course Response:", res.status, res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body).to.have.property("message").that.includes("Course deleted successfully");
  });

  it("❌ Should return 404 when deleting a non-existent course", async () => {
    const res = await request(app)
      .delete(`/instructor/course/delete/${new mongoose.Types.ObjectId()}`)
      .set("Authorization", `Bearer ${token}`);

    console.log("🚀 Delete Non-Existent Course API Response:", res.status, res.body);

    expect(res.status).to.equal(404);
    expect(res.body).to.have.property("message").that.includes("Course not found");
  });
});
