const express = require("express");
const {
  registerUser,
  loginUser,
  verifyEmail,
  updateUserDetails,
  getUserDetails
} = require("../../controllers/auth-controller/index");
const loginLimiter = require("../../middleware/rateLimit");
const authenticateMiddleware = require("../../middleware/auth-middleware");
const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/verify-email", verifyEmail);
router.put("/update", authenticateMiddleware, updateUserDetails);
router.get("/getDetails", authenticateMiddleware, getUserDetails);
router.get("/check-auth", authenticateMiddleware, (req, res) => {
  const user = req.user;

  res.status(200).json({
    success: true,
    message: "Authenticated user!",
    data: {
      user: {
        id: req.user.id,
        email: req.user.email,
        role: req.user.role
      }
    },
  });
});

module.exports = router;
