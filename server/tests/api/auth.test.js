const request = require("supertest");
const mongoose = require("mongoose");
const { app } = require("../../server");
const User = require("../../models/User");

let chai;
let expect;
let testUserVerificationToken;
let testUserEmail = "testuser@example.com";
let testUserPassword = "Password123";
let token;

before(async () => {
  chai = await import("chai");
  expect = chai.expect;
});

describe("🔐 Authentication API Tests", () => {
  before(async () => {
    if (mongoose.connection.readyState === 0) {
      const uri = process.env.TEST_DB_URI || "mongodb://localhost:27017/testdb";
      await mongoose.connect(uri);
    }
    await User.deleteMany(); // Clear test users before running tests
  });

  after(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
  });

  it("✅ Should register a new user", async () => {
    const res = await request(app).post("/auth/register").send({
      fName: "Test User",
      email: testUserEmail,
      password: testUserPassword,
      role: "student",
    });

    console.log("🚀 Registration Response:", res.body);

    expect(res.status).to.equal(201);
    expect(res.body).to.have.property("success").that.is.true;
    expect(res.body).to.have.property("message").that.includes("User registered");

    // Fetch the verification token from the database
    const user = await User.findOne({ email: testUserEmail });
    testUserVerificationToken = user.verificationToken; // Store the verification token
    expect(testUserVerificationToken).to.not.be.null;
  });

  it("✅ Should verify the test user by simulating email verification", async () => {
    const res = await request(app)
      .get(`/auth/verify-email?token=${testUserVerificationToken}`) // Simulate clicking verification link
      .send();

    console.log("🚀 Verification Response:", res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("message").that.includes("Email verified successfully");

    // Check if user is marked as verified in the database
    const verifiedUser = await User.findOne({ email: testUserEmail });
    expect(verifiedUser.verified).to.be.true;
  });

  it("✅ Should login an existing user after email verification", async () => {
    const res = await request(app).post("/auth/login").send({
      email: testUserEmail,
      password: testUserPassword,
    });

    console.log("🚀 Login API Response:", res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("data").that.has.property("accessToken");

    token = res.body.data.accessToken; // Store token for auth check test
  });

  it("❌ Should not login with incorrect password", async () => {
    const res = await request(app).post("/auth/login").send({
      email: testUserEmail,
      password: "WrongPassword123",
    });

    console.log("🚀 Invalid Login Response:", res.body);

    expect(res.status).to.equal(401);
    expect(res.body).to.have.property("message").that.includes("Invalid credentials");
  });

  it("✅ Should verify authentication with valid token", async () => {
    console.log("🚀 Sending Token:", token);

    const res = await request(app)
      .get("/auth/check-auth")
      .set("Authorization", `Bearer ${token}`);

    console.log("🚀 Auth Check Response:", res.body);

    expect(res.status).to.equal(200);
    expect(res.body).to.have.property("message").that.includes("Authenticated");
  });

  it("❌ Should fail authentication with missing token", async () => {
    const res = await request(app).get("/auth/check-auth");

    expect(res.status).to.equal(401);
    expect(res.body).to.have.property("message").that.includes("User is not authenticated");
  });

  it("❌ Should fail authentication with invalid token", async () => {
    const res = await request(app).get("/auth/check-auth").set("Authorization", "Bearer invalidtoken123");

    expect(res.status).to.equal(401);
    expect(res.body).to.have.property("message").that.includes("invalid token");
  });
});
