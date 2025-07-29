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

// Email transporter setup
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Register User with Email Verification
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
        phone,
        image: image ? sanitizeHtml(image, { allowedTags: [], allowedAttributes: {} }) : image,
        verified: false,
        verificationToken,
      });

      await newUser.save();
      logger.info('User registered successfully', { email, fName });

      // Send verification email
      const verificationLink = `http://localhost:5000/auth/verify-email?token=${verificationToken}`;
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

      await transporter.sendMail(mailOptions);
      logger.info('Verification email sent', { email });

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

// Login User
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

      logger.info('User logged in successfully', { email });
      res.status(200).json({
        success: true,
        message: "Logged in successfully",
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

// Update User Details
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
    .isIn(['user', 'admin']).withMessage('Role must be either user or admin')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

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

      const userId = req.user._id;
      const { fName, phone, image, password, role, currentPassword } = req.body;

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
        updateFields.password = await bcrypt.hash(password, salt);
      }

      if (role && req.user.role === "admin") {
        updateFields.role = role;
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

module.exports = { registerUser, verifyEmail, loginUser, updateUserDetails };