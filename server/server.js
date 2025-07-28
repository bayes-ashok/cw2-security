require("dotenv").config();
const fs = require("fs");
const https = require("https");
const path = require("path");
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const authRoutes = require("./routes/auth-routes/index");
const instructorCourseRoutes = require("./routes/instructor-routes/course-routes");
const mediaRoutes = require("./routes/instructor-routes/media-routes");
const instructorQuizRoutes = require("./routes/instructor-routes/quiz-routes");
const instructorQuestionRoutes = require("./routes/instructor-routes/question-routes");
const studentViewCourseRoutes = require("./routes/student-routes/course-routes");
const studentViewOrderRoutes = require("./routes/student-routes/order-routes");
const studentCoursesRoutes = require("./routes/student-routes/student-courses-routes");
const studentCourseProgressRoutes = require("./routes/student-routes/course-progress-routes");

const app = express();
const PORT = 443; // Use HTTPS port
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/shikshyalaya-server";

// ✅ Connect to MongoDB
async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("✅ Connected to MongoDB");
  } catch (error) {
    console.error("❌ MongoDB connection error:", error);
    process.exit(1);
  }
}

if (process.env.NODE_ENV !== "test") {
  connectDB();
}

// ✅ Middlewares
app.use(cors({
  origin: "https://localhost:5173", // Adjust based on frontend port
  credentials: true,
}));
app.use(express.json());

// ✅ Routes
app.get("/", (req, res) => {
  res.send("✅ Backend Server is Running with HTTPS!");
});
app.use("/auth", authRoutes);
app.use("/media", mediaRoutes);
app.use("/instructor/course", instructorCourseRoutes);
app.use("/instructor/quiz", instructorQuizRoutes);
app.use("/instructor/question", instructorQuestionRoutes);
app.use("/student/course", studentViewCourseRoutes);
app.use("/student/order", studentViewOrderRoutes);
app.use("/student/courses-bought", studentCoursesRoutes);
app.use("/student/course-progress", studentCourseProgressRoutes);

// ✅ Error handler
app.use((err, req, res, next) => {
  console.error("🔥 Error:", err.stack);
  res.status(500).json({
    success: false,
    message: "Something went wrong",
  });
});

// ✅ HTTPS server config
const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, "ssl", "key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "ssl", "cert.pem")),
};

// ✅ Start HTTPS server (if not in test mode)
let server;
if (process.env.NODE_ENV !== "test") {
  server = https.createServer(sslOptions, app).listen(PORT, () => {
    console.log(`✅ HTTPS server running on https://localhost:${PORT}`);
  });
}

// ✅ Export for testing
module.exports = { app, server, connectDB };
