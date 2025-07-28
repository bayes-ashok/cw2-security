const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  fName: { type: String, required: true },
  email: { type: String, required: true, unique: true }, // Ensure unique email
  password: { type: String, required: true },
  role: { type: String, required: true },
  phone: { type: String },
  image: { type: String },
  verified: { type: Boolean, default: false },
  verificationToken: { type: String },
});

module.exports = mongoose.model("User", UserSchema);
