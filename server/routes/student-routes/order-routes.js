const express = require("express");
const {
  createOrder,
  createKhaltiOrder,
  capturePaymentAndFinalizeOrder,
  verifyPayment,
  initiateKhaltiPayment,
} = require("../../controllers/student-controller/order-controller");
const authenticateMiddleware = require("../../middleware/auth-middleware");

const router = express.Router();

router.post("/create", authenticateMiddleware, createOrder);
router.post("/create-khalti", createKhaltiOrder);
router.post("/verify-payment", verifyPayment);
router.post("/capture", capturePaymentAndFinalizeOrder);
router.post("/initiate-payment", initiateKhaltiPayment);

module.exports = router;
