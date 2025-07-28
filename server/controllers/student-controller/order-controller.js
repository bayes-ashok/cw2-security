const paypal = require("../../helpers/paypal");
const Order = require("../../models/Order");
const Course = require("../../models/Course");
const User = require("../../models/User");

const StudentCourses = require("../../models/StudentCourses");
const axios = require("axios");

const createOrder = async (req, res) => {
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
                price: coursePricing,
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
        console.log(error);
        return res.status(500).json({
          success: false,
          message: "Error while creating paypal payment!",
        });
      } else {
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

        const approveUrl = paymentInfo.links.find(
          (link) => link.rel == "approval_url"
        ).href;

        res.status(201).json({
          success: true,
          data: {
            approveUrl,
            orderId: newlyCreatedCourseOrder._id,
          },
        });
      }
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      success: false,
      message: "Some error occured!",
    });
  }
};





const capturePaymentAndFinalizeOrder = async (req, res) => {
    try {
      const { paymentId, payerId, orderId } = req.body;
  
      let order = await Order.findById(orderId);
  
      if (!order) {
        return res.status(404).json({
          success: false,
          message: "Order can not be found",
        });
      }
  
      order.paymentStatus = "paid";
      order.orderStatus = "confirmed";
      order.paymentId = paymentId;
      order.payerId = payerId;
  
      await order.save();
  
      //update out student course model
      const studentCourses = await StudentCourses.findOne({
        userId: order.userId,
      });
  
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
      }
  
      //update the course schema students
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
  
      res.status(200).json({
        success: true,
        message: "Order confirmed",
        data: order,
      });
    } catch (err) {
      console.log(err);
      res.status(500).json({
        success: false,
        message: "Some error occured!",
      });
    }
  };
  

// ================================khalti==================================



let globalOrderDetails = {}; // Global variable to store the order details

const createKhaltiOrder = async (req, res) => {
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
    console.log("checkpoint")
    const coursePricin = coursePricing * 100; // Number value
    const coursePricingStr = String(coursePricin);

    // Call Khalti's payment API to initiate payment
    const response = await axios.post(
      "https://dev.khalti.com/api/v2/epayment/initiate/",
      {
        "return_url": "https://localhost:5173/payment-return",
        "website_url": "https://localhost:5173",
        "amount": coursePricingStr,
        "purchase_order_id": "order01", // Example order ID, you can generate a dynamic one
        "purchase_order_name": "Course Payment",
        "customer_info": {
          "name": fName,
          "email": email,
          "phone": phone
        }
      },
      {
        headers: {
          'Authorization': 'key 41786720168241bb94f45448c2b5f4fb',
          'Content-Type': 'application/json',
        },
      }
    );

    if (response.data.payment_url) {
      // Store the order details in the global variable
      globalOrderDetails = {
        userId,
        fName,
        email,
        orderStatus,
        paymentMethod,
        paymentStatus,
        orderDate,
        paymentId: response.data.transaction_id, // This is the transaction ID from Khalti
        payerId: userId, // Assuming userId as payerId
        instructorId,
        instructorName,
        courseImage,
        courseTitle,
        courseId,
        coursePricing,
      };


      console.log(globalOrderDetails)

      // Send the payment URL and global order details back to frontend for user to complete payment
      return res.status(200).json({
        success: true,
        payment_url: response.data.payment_url,
      });
    } else {
      return res.status(500).json({ success: false, message: "Failed to get payment URL" });
    }
  } catch (error) {
    console.error("Khalti Payment Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};




const verifyPayment = async (req, res) => {
  try {
    const { transactionId } = req.body; // Extract transactionId from the request body

    // Save the order in the Order collection
    const newOrder = new Order({
      userId: globalOrderDetails.userId,
      fName: globalOrderDetails.fName,
      email: globalOrderDetails.email,
      orderStatus: "confirmed",
      paymentMethod: "khalti",
      paymentStatus: "paid",
      orderDate: new Date(globalOrderDetails.orderDate),
      paymentId: transactionId || null, // Store the transactionId in paymentId
      payerId: globalOrderDetails.payerId,
      instructorId: globalOrderDetails.instructorId,
      instructorName: globalOrderDetails.instructorName,
      courseImage: globalOrderDetails.courseImage,
      courseTitle: globalOrderDetails.courseTitle,
      courseId: globalOrderDetails.courseId,
      coursePricing: globalOrderDetails.coursePricing.toString() // Ensure it's a string
    });

    await newOrder.save(); // Save the new order to the database
    console.log("Order saved successfully!");

    // Now update the student's courses
    const { userId, fName, email, courseId, courseTitle, instructorId, instructorName, courseImage, coursePricing } = globalOrderDetails;

    // Check if the student already has a record in the StudentCourses collection
    let studentCourses = await StudentCourses.findOne({ userId });

    const courseDetails = {
      courseId,
      title: courseTitle,
      instructorId,
      instructorName,
      dateOfPurchase: new Date(), // The date when the course was purchased
      courseImage,
    };

    if (studentCourses) {
      // If the student already has a record, add the new course to their courses array
      studentCourses.courses.push(courseDetails);
    } else {
      // If the student doesn't have a record, create a new one
      studentCourses = new StudentCourses({
        userId,
        courses: [courseDetails], // Add the first course to the array
      });
    }

    await studentCourses.save(); // Save or update the student's courses
    console.log("Student course record updated successfully!");

    // Now update the Course collection to add the student
    const course = await Course.findOne({ _id: courseId });

    if (course) {
      // Check if the student is already in the students list
      const studentExists = course.students.some((student) => student.studentId === userId);

      if (!studentExists) {
        course.students.push({
          studentId: userId,
          studentName: fName,
          studentEmail: email,
          paidAmount: coursePricing.toString(),
        });

        await course.save();
        console.log("Student added to the course successfully!");
      } else {
        console.log("Student already enrolled in the course.");
      }
    } else {
      console.error("Course not found!");
      return res.status(404).json({ message: "Course not found!" });
    }

    // Respond to the frontend
    res.status(200).json({ message: "Payment verified and course added successfully" });
  } catch (error) {
    console.error("Error saving order, updating student courses, or updating course students:", error);
    res.status(500).json({ message: "Error processing payment and updating records" }); // Handle errors properly
  }
};

const jwt = require('jsonwebtoken');  // If using JWT for userToken

// Safe Stringify function to handle circular references
const safeStringify = (obj) => {
  try {
    return JSON.stringify(obj);
  } catch (error) {
    return '[Circular reference]'; // Return a placeholder if circular reference is detected
  }
};



const initiateKhaltiPayment = async (req, res) => {
  try {
    const { userId, fName, email, phone, coursePricing } = req.body;

    const amountInPaisa = coursePricing * 100; // Convert to paisa
    const amountStr = String(amountInPaisa);

    // Khalti API request payload
    const khaltiPayload = {
      return_url: "http://localhost:5173/payment-return",
      website_url: "http://localhost:5173",
      amount: amountStr,
      purchase_order_id: `order_${userId}_${Date.now()}`, // Dynamic order ID
      purchase_order_name: "Course Payment",
      customer_info: {
        name: fName,
        email,
        phone,
      },
    };

    // Make request to Khalti API
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
      return res.status(200).json({
        success: true,
        payment_url: response.data.payment_url,
        transaction_id: response.data.transaction_id, // Pass transaction ID for reference
      });
    } else {
      return res.status(500).json({
        success: false,
        message: "Failed to get payment URL",
      });
    }
  } catch (error) {
    console.error("Khalti Payment Error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = { createOrder, capturePaymentAndFinalizeOrder, createKhaltiOrder, verifyPayment,initiateKhaltiPayment };
