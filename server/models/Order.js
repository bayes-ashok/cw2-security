const mongoose = require("mongoose");

const OrderSchema = new mongoose.Schema({
  userId: String,
  fName: String,
  email: String,
  orderStatus: String,
  paymentMethod: String,
  paymentStatus: String,
  orderDate: Date,
  paymentId: String,
  payerId: String,
  instructorId: String,
  instructorName: String,
  courseImage: String,
  courseTitle: String,
  courseId: String,
  coursePricing: String,
});

module.exports = mongoose.model("Order", OrderSchema);
