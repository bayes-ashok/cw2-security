const { body, validationResult } = require('express-validator');
const paypal = require("../../helpers/paypal");
const Order = require("../../models/Order");
const Course = require("../../models/Course");
const User = require("../../models/User");
const StudentCourses = require("../../models/StudentCourses");
const axios = require("axios");
const sanitizeHtml = require('sanitize-html');
const logger = require("../../middleware/logger");

const createOrder = [
  // Validation rules
  body('userId')
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('fName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2 }).withMessage('First name must be at least 2 characters long')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('email')
    .isEmail().withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('orderStatus')
    .notEmpty().withMessage('Order status is required')
    .isIn(['pending', 'confirmed']).withMessage('Invalid order status')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('paymentMethod')
    .notEmpty().withMessage('Payment method is required')
    .isIn(['paypal']).withMessage('Invalid payment method')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('paymentStatus')
    .notEmpty().withMessage('Payment status is required')
    .isIn(['pending', 'paid']).withMessage('Invalid payment status')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('orderDate')
    .notEmpty().withMessage('Order date is required')
    .isISO8601().withMessage('Invalid date format')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('paymentId')
    .optional()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('payerId')
    .optional()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('instructorId')
    .notEmpty().withMessage('Instructor ID is required')
    .isMongoId().withMessage('Invalid instructor ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('instructorName')
    .trim()
    .notEmpty().withMessage('Instructor name is required')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('courseImage')
    .optional()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('courseTitle')
    .trim()
    .notEmpty().withMessage('Course title is required')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('courseId')
    .notEmpty().withMessage('Course ID is required')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('coursePricing')
    .notEmpty().withMessage('Course pricing is required')
    .isFloat({ min: 0 }).withMessage('Course pricing must be a positive number')
    .customSanitizer((value) => sanitizeHtml(value.toString(), { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during PayPal order creation', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const {
        userId,
        fName,
        email,
        orderStatus,
        paymentMethod,
        paymentStatus,
        orderDate,
        paymentId,
        payerId,
        instructorId,
        instructorName,
        courseImage,
        courseTitle,
        courseId,
        coursePricing,
      } = req.body;

      const create_payment_json = {
        intent: "sale",
        payer: {
          payment_method: "paypal",
        },
        redirect_urls: {
          return_url: "http://localhost:5173/paypal-return",
          cancel_url: "http://localhost:5173/payment-cancel",
        },
        transactions: [
          {
            item_list: {
              items: [
                {
                  name: courseTitle,
                  sku: courseId,
                  price: coursePricing.toFixed(2),
                  currency: "USD",
                  quantity: 1,
                },
              ],
            },
            amount: {
              currency: "USD",
              total: coursePricing.toFixed(2),
            },
            description: courseTitle,
          },
        ],
      };

      paypal.payment.create(create_payment_json, async (error, paymentInfo) => {
        if (error) {
          logger.error('Error creating PayPal payment', { error: error.message });
          return res.status(500).json({
            success: false,
            message: "Error while creating PayPal payment",
          });
        }

        const newlyCreatedCourseOrder = new Order({
          userId,
          fName,
          email,
          orderStatus,
          paymentMethod,
          paymentStatus,
          orderDate,
          paymentId,
          payerId,
          instructorId,
          instructorName,
          courseImage,
          courseTitle,
          courseId,
          coursePricing,
        });

        await newlyCreatedCourseOrder.save();
        logger.info('PayPal order created successfully', { orderId: newlyCreatedCourseOrder._id, courseId });

        const approveUrl = paymentInfo.links.find(
          (link) => link.rel === "approval_url"
        ).href;

        res.status(201).json({
          success: true,
          data: {
            approveUrl,
            orderId: newlyCreatedCourseOrder._id,
          },
        });
      });
    } catch (error) {
      logger.error('Error during PayPal order creation', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const capturePaymentAndFinalizeOrder = [
  // Validation rules
  body('paymentId')
    .notEmpty().withMessage('Payment ID is required')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('payerId')
    .notEmpty().withMessage('Payer ID is required')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('orderId')
    .notEmpty().withMessage('Order ID is required')
    .isMongoId().withMessage('Invalid order ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during PayPal payment capture', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { paymentId, payerId, orderId } = req.body;

      let order = await Order.findById(orderId);
      if (!order) {
        logger.warn('Order not found during payment capture', { orderId });
        return res.status(404).json({
          success: false,
          message: "Order not found",
        });
      }

      order.paymentStatus = "paid";
      order.orderStatus = "confirmed";
      order.paymentId = paymentId;
      order.payerId = payerId;
      await order.save();
      logger.info('PayPal payment captured and order finalized', { orderId, courseId: order.courseId });

      let studentCourses = await StudentCourses.findOne({ userId: order.userId });
      if (studentCourses) {
        studentCourses.courses.push({
          courseId: order.courseId,
          title: order.courseTitle,
          instructorId: order.instructorId,
          instructorName: order.instructorName,
          dateOfPurchase: order.orderDate,
          courseImage: order.courseImage,
        });
        await studentCourses.save();
        logger.info('Student courses updated', { userId: order.userId, courseId: order.courseId });
      } else {
        const newStudentCourses = new StudentCourses({
          userId: order.userId,
          courses: [
            {
              courseId: order.courseId,
              title: order.courseTitle,
              instructorId: order.instructorId,
              instructorName: order.instructorName,
              dateOfPurchase: order.orderDate,
              courseImage: order.courseImage,
            },
          ],
        });
        await newStudentCourses.save();
        logger.info('New student courses record created', { userId: order.userId, courseId: order.courseId });
      }

      await Course.findByIdAndUpdate(order.courseId, {
        $addToSet: {
          students: {
            studentId: order.userId,
            studentName: order.fName,
            studentEmail: order.email,
            paidAmount: order.coursePricing,
          },
        },
      });
      logger.info('Course students updated', { courseId: order.courseId, studentId: order.userId });

      res.status(200).json({
        success: true,
        message: "Order confirmed",
        data: order,
      });
    } catch (error) {
      logger.error('Error capturing PayPal payment', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

let globalOrderDetails = {};

const createKhaltiOrder = [
  // Validation rules
  body('userId')
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('fName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2 }).withMessage('First name must be at least 2 characters long')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('email')
    .isEmail().withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('phone')
    .notEmpty().withMessage('Phone number is required')
    .isMobilePhone().withMessage('Invalid phone number')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('orderStatus')
    .notEmpty().withMessage('Order status is required')
    .isIn(['pending', 'confirmed']).withMessage('Invalid order status')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('paymentMethod')
    .notEmpty().withMessage('Payment method is required')
    .isIn(['khalti']).withMessage('Invalid payment method')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('paymentStatus')
    .notEmpty().withMessage('Payment status is required')
    .isIn(['pending', 'paid']).withMessage('Invalid payment status')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('orderDate')
    .notEmpty().withMessage('Order date is required')
    .isISO8601().withMessage('Invalid date format')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('paymentId')
    .optional()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('payerId')
    .optional()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('instructorId')
    .notEmpty().withMessage('Instructor ID is required')
    .isMongoId().withMessage('Invalid instructor ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('instructorName')
    .trim()
    .notEmpty().withMessage('Instructor name is required')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('courseImage')
    .optional()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('courseTitle')
    .trim()
    .notEmpty().withMessage('Course title is required')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('courseId')
    .notEmpty().withMessage('Course ID is required')
    .isMongoId().withMessage('Invalid course ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('coursePricing')
    .notEmpty().withMessage('Course pricing is required')
    .isFloat({ min: 0 }).withMessage('Course pricing must be a positive number')
    .customSanitizer((value) => sanitizeHtml(value.toString(), { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during Khalti order creation', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const {
        userId,
        fName,
        email,
        phone,
        orderStatus,
        paymentMethod,
        paymentStatus,
        orderDate,
        paymentId,
        payerId,
        instructorId,
        instructorName,
        courseImage,
        courseTitle,
        courseId,
        coursePricing,
      } = req.body;

      const coursePricin = coursePricing * 100;
      const coursePricingStr = String(coursePricin);

      const response = await axios.post(
        "https://dev.khalti.com/api/v2/epayment/initiate/",
        {
          return_url: "http://localhost:5173/payment-return",
          website_url: "http://localhost:5173",
          amount: coursePricingStr,
          purchase_order_id: `order_${userId}_${Date.now()}`,
          purchase_order_name: "Course Payment",
          customer_info: {
            name: fName,
            email,
            phone,
          },
        },
        {
          headers: {
            Authorization: 'key 41786720168241bb94f45448c2b5f4fb',
            'Content-Type': 'application/json',
          },
        }
      );

      if (response.data.payment_url) {
        globalOrderDetails = {
          userId,
          fName,
          email,
          orderStatus,
          paymentMethod,
          paymentStatus,
          orderDate,
          paymentId: response.data.transaction_id,
          payerId: userId,
          instructorId,
          instructorName,
          courseImage,
          courseTitle,
          courseId,
          coursePricing,
        };
        logger.info('Khalti order initiated', { transactionId: response.data.transaction_id, courseId });

        res.status(200).json({
          success: true,
          payment_url: response.data.payment_url,
        });
      } else {
        logger.warn('Failed to get Khalti payment URL', { courseId });
        res.status(500).json({ success: false, message: "Failed to get payment URL" });
      }
    } catch (error) {
      logger.error('Error during Khalti order creation', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const verifyPayment = [
  // Validation rules
  body('transactionId')
    .notEmpty().withMessage('Transaction ID is required')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during Khalti payment verification', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { transactionId } = req.body;

      const newOrder = new Order({
        userId: globalOrderDetails.userId,
        fName: globalOrderDetails.fName,
        email: globalOrderDetails.email,
        orderStatus: "confirmed",
        paymentMethod: "khalti",
        paymentStatus: "paid",
        orderDate: new Date(globalOrderDetails.orderDate),
        paymentId: transactionId || null,
        payerId: globalOrderDetails.payerId,
        instructorId: globalOrderDetails.instructorId,
        instructorName: globalOrderDetails.instructorName,
        courseImage: globalOrderDetails.courseImage,
        courseTitle: globalOrderDetails.courseTitle,
        courseId: globalOrderDetails.courseId,
        coursePricing: globalOrderDetails.coursePricing.toString(),
      });

      await newOrder.save();
      logger.info('Khalti order saved successfully', { orderId: newOrder._id, courseId: newOrder.courseId });

      let studentCourses = await StudentCourses.findOne({ userId: globalOrderDetails.userId });
      const courseDetails = {
        courseId: globalOrderDetails.courseId,
        title: globalOrderDetails.courseTitle,
        instructorId: globalOrderDetails.instructorId,
        instructorName: globalOrderDetails.instructorName,
        dateOfPurchase: new Date(),
        courseImage: globalOrderDetails.courseImage,
      };

      if (studentCourses) {
        studentCourses.courses.push(courseDetails);
        await studentCourses.save();
        logger.info('Student courses updated', { userId: globalOrderDetails.userId, courseId: globalOrderDetails.courseId });
      } else {
        studentCourses = new StudentCourses({
          userId: globalOrderDetails.userId,
          courses: [courseDetails],
        });
        await studentCourses.save();
        logger.info('New student courses record created', { userId: globalOrderDetails.userId, courseId: globalOrderDetails.courseId });
      }

      const course = await Course.findOne({ _id: globalOrderDetails.courseId });
      if (course) {
        const studentExists = course.students.some((student) => student.studentId.toString() === globalOrderDetails.userId);
        if (!studentExists) {
          course.students.push({
            studentId: globalOrderDetails.userId,
            studentName: globalOrderDetails.fName,
            studentEmail: globalOrderDetails.email,
            paidAmount: globalOrderDetails.coursePricing.toString(),
          });
          await course.save();
          logger.info('Student added to course', { courseId: globalOrderDetails.courseId, studentId: globalOrderDetails.userId });
        } else {
          logger.info('Student already enrolled in course', { courseId: globalOrderDetails.courseId, studentId: globalOrderDetails.userId });
        }
      } else {
        logger.warn('Course not found during payment verification', { courseId: globalOrderDetails.courseId });
        return res.status(404).json({ success: false, message: "Course not found" });
      }

      res.status(200).json({
        success: true,
        message: "Payment verified and course added successfully",
      });
    } catch (error) {
      logger.error('Error verifying Khalti payment', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

const initiateKhaltiPayment = [
  // Validation rules
  body('userId')
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('fName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2 }).withMessage('First name must be at least 2 characters long')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('email')
    .isEmail().withMessage('Please provide a valid email address')
    .normalizeEmail()
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('phone')
    .notEmpty().withMessage('Phone number is required')
    .isMobilePhone().withMessage('Invalid phone number')
    .customSanitizer((value) => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  body('coursePricing')
    .notEmpty().withMessage('Course pricing is required')
    .isFloat({ min: 0 }).withMessage('Course pricing must be a positive number')
    .customSanitizer((value) => sanitizeHtml(value.toString(), { allowedTags: [], allowedAttributes: {} })),

  // Controller logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.error('Validation errors during Khalti payment initiation', { errors: errors.array() });
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { userId, fName, email, phone, coursePricing } = req.body;

      const amountInPaisa = coursePricing * 100;
      const amountStr = String(amountInPaisa);

      const khaltiPayload = {
        return_url: "http://localhost:5173/payment-return",
        website_url: "http://localhost:5173",
        amount: amountStr,
        purchase_order_id: `order_${userId}_${Date.now()}`,
        purchase_order_name: "Course Payment",
        customer_info: {
          name: fName,
          email,
          phone,
        },
      };

      const response = await axios.post(
        "https://dev.khalti.com/api/v2/epayment/initiate/",
        khaltiPayload,
        {
          headers: {
            Authorization: "key 41786720168241bb94f45448c2b5f4fb",
            "Content-Type": "application/json",
          },
        }
      );

      if (response.data.payment_url) {
        logger.info('Khalti payment initiated', { transactionId: response.data.transaction_id, userId });
        res.status(200).json({
          success: true,
          payment_url: response.data.payment_url,
          transaction_id: response.data.transaction_id,
        });
      } else {
        logger.warn('Failed to get Khalti payment URL', { userId });
        res.status(500).json({
          success: false,
          message: "Failed to get payment URL",
        });
      }
    } catch (error) {
      logger.error('Error initiating Khalti payment', { error: error.message });
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error.message,
      });
    }
  }
];

module.exports = {
  createOrder,
  capturePaymentAndFinalizeOrder,
  createKhaltiOrder,
  verifyPayment,
  initiateKhaltiPayment
};