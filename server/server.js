require("dotenv").config();
const fs = require("fs");
const https = require("https");
const path = require("path");
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const helmet = require("helmet");
const winston = require("winston");
const { validationResult } = require("express-validator");

const authRoutes = require("./routes/auth-routes/index");
const instructorCourseRoutes = require("./routes/instructor-routes/course-routes");
const mediaRoutes = require("./routes/instructor-routes/media-routes");
const studentViewCourseRoutes = require("./routes/student-routes/course-routes");
const studentViewOrderRoutes = require("./routes/student-routes/order-routes");
const studentCoursesRoutes = require("./routes/student-routes/student-courses-routes");
const studentCourseProgressRoutes = require("./routes/student-routes/course-progress-routes");

const app = express();

// ✅ Environment Variables
const PORT = process.env.SERVER_PORT || 443;
const HOST = process.env.SERVER_HOST || "0.0.0.0";
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/shikshyalaya-server";

// ✅ Logger
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()],
});

// ✅ Connect to MongoDB
async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI);
    logger.info("✅ Connected to MongoDB");
  } catch (error) {
    logger.error("❌ MongoDB connection error:", error);
    process.exit(1);
  }
}

if (process.env.NODE_ENV !== "test") {
  connectDB();
}

// Disabled x-powered-by header to prevent exposing server technology
app.disable("x-powered-by");

// ✅ CORS
app.use(cors({
  origin: [process.env.CLIENT_URL, "https://192.168.1.72:5173"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// ✅ Helmet with strict CSP
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
  })
);

app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", process.env.CLIENT_URL],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", process.env.CLIENT_URL],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

// ✅ Extra Security Headers
app.use(helmet.referrerPolicy({ policy: "no-referrer" }));
app.use(helmet.frameguard({ action: "deny" }));

// ✅ Input Validation Middleware
function validateRequest(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map((err) => ({
        field: err.param,
        message: err.msg,
      })),
    });
  }
  next();
}

// ✅ Routes
app.get("/", (req, res) => {
  res.send("✅ Backend Server is Running with HTTPS & Security!");
});

app.use("/auth", authRoutes);
app.use("/media", mediaRoutes);
app.use("/instructor/course", instructorCourseRoutes);
app.use("/student/course", studentViewCourseRoutes);
app.use("/student/order", studentViewOrderRoutes);
app.use("/student/courses-bought", studentCoursesRoutes);
app.use("/student/course-progress", studentCourseProgressRoutes);

// ✅ Error Handler
app.use((err, req, res, next) => {
  logger.error(err.stack);
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

const server = https.createServer(sslOptions, app).listen(PORT, HOST, () => {
  logger.info(`✅ HTTPS server running on https://${HOST}:${PORT}`);
});

module.exports = { app, server, connectDB, validateRequest };
