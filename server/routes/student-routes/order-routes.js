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
router.post("/create-khalti", authenticateMiddleware,createKhaltiOrder);
router.post("/verify-payment", authenticateMiddleware, verifyPayment);
router.post("/capture", authenticateMiddleware, capturePaymentAndFinalizeOrder);
router.post("/initiate-payment", authenticateMiddleware, initiateKhaltiPayment);

module.exports = router;
