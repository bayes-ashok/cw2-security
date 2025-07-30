const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  fName: { type: String, required: true },
  email: { type: String, required: true, unique: true }, // Unique email
  password: { type: String, required: true },
  prevPasswords: { type: [String], default: [] }, // Store old hashed passwords
  role: { type: String, required: true },
  phone: { type: String },
  image: { type: String },
  verified: { type: Boolean, default: false },
  verificationToken: { type: String },
  // Security enhancements
  loginAttempts: { type: Number, default: 0 }, // Track failed logins
  lockUntil: { type: Date }, // Lock account timestamp
  twoFactorEnabled: { type: Boolean, default: false }, // Enable 2FA
  otp: { type: String }, // Store OTP
  otpExpires: { type: Date }, // OTP expiration time
}, { timestamps: true });

module.exports = mongoose.model("User", UserSchema);