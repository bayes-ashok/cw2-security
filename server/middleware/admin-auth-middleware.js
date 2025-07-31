const jwt = require("jsonwebtoken");
const User = require("../models/User");

const verifyToken = (token, secretKey) => {
  return jwt.verify(token, secretKey);
};

const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  console.log(authHeader, "authHeader");

  if (!authHeader) {
    return res.status(401).json({
      success: false,
      message: "User is not authenticated",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = verifyToken(token, "JWT_SECRET");

    // ✅ Attach user details
    req.user = {
      id: payload._id,
      fName: payload.fName,
      email: payload.email,
      role: payload.role,
      phone: payload.phone,
      image: payload.image
    };

    // ✅ Check user role from DB to ensure not tampered token
    const user = await User.findById(payload._id).select("role");
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.role !== "instructor") {
      return res.status(403).json({
        success: false,
        message: "Access denied: Admins only",
      });
    }

    next();
  } catch (e) {
    console.error("Admin Auth Error:", e.message);
    return res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
};

module.exports = authenticateAdmin;
