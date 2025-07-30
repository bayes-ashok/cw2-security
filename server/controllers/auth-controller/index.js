const { body, validationResult } = require('express-validator');
const User = require("../../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const sanitizeHtml = require('sanitize-html');
require("dotenv").config();
const axios = require("axios");
const logger = require("../../middleware/logger");

// Log environment variables for debugging
console.log("Email User:", process.env.EMAIL_USER);
console.log("Email Pass:", process.env.EMAIL_PASS ? "Set" : "Not Set");

// Email transporter setup
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Generate a 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const registerUser = [
  // Validation rules
  body('fName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2 }).withMessage('First name must be at least 2 characters long')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('email')
    .isEmail().withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('password')
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  body('phone')
    .optional()
    .isMobilePhone().withMessage('Please provide a valid phone number')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('captchaToken')
    .notEmpty().withMessage('Captcha token is required')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during user registration', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      let { fName, email, password, phone, image, captchaToken } = req.body;
      const captchaVerifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captchaToken}`;
      const captchaRes = await axios.post(captchaVerifyURL);
      if (!captchaRes.data.success) {
        logger.warn('Captcha verification failed', { email });
        return res.status(400).json({ success: false, message: "Captcha verification failed" });
      }
      const role = "user";

      const existingUser = await User.findOne({ $or: [{ email }, { fName }] });
      if (existingUser) {
        logger.warn('User name or email already exists', { email, fName });
        return res.status(400).json({
          success: false,
          message: "User name or email already exists",
        });
      }

      const hashPassword = await bcrypt.hash(password, 10);
      const verificationToken = crypto.randomBytes(32).toString("hex");

      const newUser = new User({
        fName,
        email,
        role,
        password: hashPassword,
        prevPasswords: [hashPassword], // Store the hashed password in prevPasswords
        phone,
        image: image ? sanitizeHtml(image, { allowedTags: [], allowedAttributes: {} }) : image,
        verified: false,
        verificationToken,
        lastPasswordChange: Date.now(), // Set initial password change date
      });

      await newUser.save();
      logger.info('User registered successfully', { email, fName });

      // Send verification email
      const verificationLink = `https://localhost:443/auth/verify-email?token=${verificationToken}`;
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Verify Your Email",
        html: sanitizeHtml(
          `<p>Click the link below to verify your email:</p>
           <a href="${verificationLink}">Verify Email</a>`,
          { allowedTags: ['p', 'a'], allowedAttributes: { 'a': ['href'] } }
        ),
      };

      try {
        await transporter.sendMail(mailOptions);
        logger.info('Verification email sent', { email });
      } catch (emailError) {
        logger.error('Failed to send verification email', { email, error: emailError.message });
        return res.status(500).json({
          success: false,
          message: "User registered, but failed to send verification email. Please try again later.",
          error: emailError.message,
        });
      }

      res.status(201).json({
        success: true,
        message: "User registered successfully! Please check your email to verify your account.",
      });
    } catch (error) {
      logger.error('Error during user registration', { error: error.message });
      res.status(500).json({ success: false, message: "Internal server error", error: error.message });
    }
  }
];

// Verify Email
const verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;
    const sanitizedToken = sanitizeHtml(token, { allowedTags: [], allowedAttributes: {} });

    const user = await User.findOne({ verificationToken: sanitizedToken });
    if (!user) {
      logger.warn('Invalid or expired verification token', { token: sanitizedToken });
      return res.status(400).json({ success: false, message: "Invalid or expired token" });
    }

    user.verified = true;
    user.verificationToken = null;
    await user.save();
    logger.info('Email verified successfully', { email: user.email });

    res.status(200).json({ success: true, message: "Email verified successfully! You can now log in." });
  } catch (error) {
    logger.error('Error during email verification', { error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
};
const loginUser = [
  body('email')
    .isEmail().withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('password')
    .notEmpty().withMessage('Password is required'),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during login', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { email, password } = req.body;
    const LOCK_TIME = 5 * 60 * 1000; // 5 minutes in ms
    const MAX_ATTEMPTS = 5;
    const ONE_MONTH = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds

    try {
      const checkUser = await User.findOne({ email });
      if (!checkUser) {
        logger.warn('Invalid login attempt - user not found', { email });
        return res.status(401).json({ success: false, message: "Invalid credentials" });
      }

      if (checkUser.lockUntil && checkUser.lockUntil > Date.now()) {
        const remaining = Math.ceil((checkUser.lockUntil - Date.now()) / 1000);
        logger.warn('Account locked during login attempt', { email, remaining });
        return res.status(403).json({
          success: false,
          message: `Account locked. Try again after ${remaining} seconds.`,
        });
      }

      const isMatch = await bcrypt.compare(password, checkUser.password);
      if (!isMatch) {
        checkUser.loginAttempts += 1;
        if (checkUser.loginAttempts >= MAX_ATTEMPTS) {
          checkUser.lockUntil = Date.now() + LOCK_TIME;
          await checkUser.save();
          logger.warn('Account locked due to too many failed login attempts', { email });
          return res.status(403).json({
            success: false,
            message: "Too many failed attempts. Account locked for 5 minutes.",
          });
        }

        await checkUser.save();
        logger.warn('Invalid login attempt - incorrect password', { email, loginAttempts: checkUser.loginAttempts });
        return res.status(401).json({ success: false, message: "Invalid credentials" });
      }

      checkUser.loginAttempts = 0;
      checkUser.lockUntil = undefined;
      await checkUser.save();

      if (!checkUser.verified) {
        logger.warn('Login attempt with unverified account', { email });
        return res.status(403).json({
          success: false,
          message: "Your account is not verified. Please check your email.",
        });
      }

      // Check if password change is recommended
      const isPasswordChangeRecommended = checkUser.lastPasswordChange &&
        Date.now() - new Date(checkUser.lastPasswordChange).getTime() > ONE_MONTH;

      if (checkUser.twoFactorEnabled) {
        // Generate and store OTP
        const otp = generateOTP();
        const otpExpires = Date.now() + 5 * 60 * 1000; // 5 minutes expiration
        checkUser.otp = otp;
        checkUser.otpExpires = otpExpires;
        await checkUser.save();

        // Send OTP email
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Your OTP for Login",
          html: sanitizeHtml(
            `<p>Your one-time password (OTP) is <strong>${otp}</strong>. It expires in 5 minutes.</p>`,
            { allowedTags: ['p', 'strong'], allowedAttributes: {} }
          ),
        };

        try {
          await transporter.sendMail(mailOptions);
          logger.info('OTP sent to user', { email });
        } catch (emailError) {
          logger.error('Failed to send OTP email', { email, error: emailError.message });
          return res.status(500).json({
            success: false,
            message: "Failed to send OTP email. Please try again later.",
            error: emailError.message,
          });
        }

        return res.status(200).json({
          success: true,
          message: "OTP sent to your email. Please verify to complete login.",
          data: { userId: checkUser._id, requiresOtp: true },
        });
      }

      const accessToken = jwt.sign(
        {
          _id: checkUser._id,
          fName: checkUser.fName,
          email: checkUser.email,
          role: checkUser.role,
          phone: checkUser.phone,
          image: checkUser.image,
        },
        "JWT_SECRET",
        { expiresIn: "120m" }
      );

      // Set response message based on password age
      let message = "Logged in successfully";
      if (isPasswordChangeRecommended) {
        message = "Logged in successfully. \nWe recommend changing your password as it has been over a month since your last update.";
      }

      logger.info('User logged in successfully', { email });
      res.status(200).json({
        success: true,
        message,
        data: {
          accessToken,
          user: {
            _id: checkUser._id,
            fName: checkUser.fName,
            email: checkUser.email,
            role: checkUser.role,
            phone: checkUser.phone,
            image: checkUser.image,
          },
        },
      });
    } catch (error) {
      logger.error('Error during login', { error: error.message });
      res.status(500).json({ success: false, message: "Internal server error", error: error.message });
    }
  }
];

// Verify OTP
const verifyOTP = [
  body('userId')
    .notEmpty().withMessage('User ID is required'),
  body('otp')
    .notEmpty().withMessage('OTP is required')
    .isNumeric().withMessage('OTP must be numeric')
    .isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during OTP verification', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { userId, otp } = req.body;
    const ONE_MONTH = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds

    try {
      const user = await User.findById(userId);
      if (!user) {
        logger.warn('User not found during OTP verification', { userId });
        return res.status(404).json({ success: false, message: "User not found" });
      }

      if (!user.otp || !user.otpExpires || user.otpExpires < Date.now()) {
        logger.warn('Invalid or expired OTP', { userId });
        return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
      }

      if (user.otp !== otp) {
        logger.warn('Incorrect OTP provided', { userId });
        return res.status(400).json({ success: false, message: "Incorrect OTP" });
      }

      // Clear OTP fields
      user.otp = undefined;
      user.otpExpires = undefined;
      await user.save();

      // Check if password change is required
      const passwordChangeRequired = user.lastPasswordChange &&
        Date.now() - new Date(user.lastPasswordChange).getTime() > ONE_MONTH;

      const accessToken = jwt.sign(
        {
          _id: user._id,
          fName: user.fName,
          email: user.email,
          role: user.role,
          phone: user.phone,
          image: user.image,
          passwordChangeRequired, // Include in token
        },
        "JWT_SECRET",
        { expiresIn: "120m" }
      );

      logger.info('OTP verified and user logged in successfully', { email: user.email });
      res.status(200).json({
        success: true,
        message: "OTP verified successfully. Logged in successfully.",
        data: {
          accessToken,
          user: {
            _id: user._id,
            fName: user.fName,
            email: user.email,
            role: user.role,
            phone: user.phone,
            image: user.image,
            passwordChangeRequired,
          },
        },
      });
    } catch (error) {
      logger.error('Error during OTP verification', { error: error.message });
      res.status(500).json({ success: false, message: "Internal server error", error: error.message });
    }
  }
];

const updateUserDetails = [
  body('fName')
    .optional()
    .trim()
    .isLength({ min: 2 }).withMessage('First name must be at least 2 characters long')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('phone')
    .optional()
    .isMobilePhone().withMessage('Please provide a valid phone number')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('password')
    .optional()
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  body('currentPassword')
    .notEmpty().withMessage('Current password is required'),
  body('role')
    .optional()
    .isIn(['user']).withMessage('Role must be either user')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('twoFactorEnabled')
    .optional()
    .isBoolean().withMessage('Two-factor enabled must be a boolean'),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during user update', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      if (!req.user) {
        logger.warn('Unauthorized access attempt during user update');
        return res.status(401).json({ success: false, message: "Unauthorized access" });
      }

      const userId = req.user.id;
      const { fName, phone, image, password, currentPassword, twoFactorEnabled } = req.body;
      const role = 'user';
      const user = await User.findById(userId);
      if (!user) {
        logger.warn('User not found during update', { userId });
        return res.status(404).json({ success: false, message: "User not found" });
      }

      const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isPasswordValid) {
        logger.warn('Incorrect current password during user update', { userId });
        return res.status(401).json({ success: false, message: "Incorrect current password" });
      }

      let updateFields = {};
      if (fName) updateFields.fName = fName;
      if (phone) updateFields.phone = phone;
      if (image) updateFields.image = sanitizeHtml(image, { allowedTags: [], allowedAttributes: {} });
      if (password) {
        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(password, salt);
        // Check if new password matches any previous passwords
        for (const prevPassword of user.prevPasswords) {
          if (await bcrypt.compare(password, prevPassword)) {
            logger.warn('New password matches a previous password', { userId });
            return res.status(400).json({
              success: false,
              message: "This password is already used. Please try new password.",
            });
          }
        }
        updateFields.password = hashedNewPassword;
        updateFields.prevPasswords = [...user.prevPasswords, user.password].slice(-5);
        updateFields.lastPasswordChange = Date.now(); // Update password change date
      }
      if (twoFactorEnabled !== undefined) {
        updateFields.twoFactorEnabled = twoFactorEnabled;
      }

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $set: updateFields },
        { new: true, runValidators: true }
      ).select("-password");

      logger.info('User details updated successfully', { userId, email: user.email });
      res.status(200).json({
        success: true,
        message: "User details updated successfully",
        user: updatedUser,
      });
    } catch (error) {
      logger.error('Error updating user', { error: error.message });
      res.status(500).json({ success: false, message: "Internal server error", error: error.message });
    }
  }
];

// Get User Details
const getUserDetails = async (req, res) => {
  try {
    if (!req.user) {
      logger.warn('Unauthorized access attempt during user details fetch');
      return res.status(401).json({ success: false, message: "Unauthorized access" });
    }

    const userId = req.user.id;
    const user = await User.findById(userId).select('fName phone twoFactorEnabled lastPasswordChange');

    if (!user) {
      logger.warn('User not found during details fetch', { userId });
      return res.status(404).json({ success: false, message: "User not found" });
    }

    logger.info('User details fetched successfully', { userId, email: user.email });
    res.status(200).json({
      success: true,
      user: {
        fName: user.fName,
        phone: user.phone,
        twoFactorEnabled: user.twoFactorEnabled,
        lastPasswordChange: user.lastPasswordChange,
      }
    });
  } catch (error) {
    logger.error('Error fetching user details', { error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
};

// Middleware to check if password change is required
const requirePasswordChange = async (req, res, next) => {
  const ONE_MONTH = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);
    if (!user) {
      logger.warn('User not found during password change check', { userId });
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (user.lastPasswordChange && Date.now() - new Date(user.lastPasswordChange).getTime() > ONE_MONTH) {
      logger.warn('Password change required', { userId, email: user.email });
      return res.status(403).json({
        success: false,
        message: "Password change required. Please update your password to access the dashboard.",
        passwordChangeRequired: true,
      });
    }

    next();
  } catch (error) {
    logger.error('Error checking password change requirement', { error: error.message });
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
};

module.exports = { registerUser, verifyEmail, loginUser, verifyOTP, updateUserDetails, getUserDetails, requirePasswordChange };