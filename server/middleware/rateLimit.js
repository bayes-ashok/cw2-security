// middleware/rateLimit.js
const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { success: false, message: "Too many attempts, try again later." },
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = loginLimiter;
