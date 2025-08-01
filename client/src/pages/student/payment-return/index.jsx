import React, { useEffect, useState } from "react";
import axios from "axios";

const PaymentReturnPage = () => {
  const [paymentStatus, setPaymentStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);

    // ✅ Read token from return_url
    const token = params.get("token");
    if (token) {
      console.log("✅ Restored token from URL:", token);
      localStorage.setItem("accessToken", JSON.stringify(token)); // or sessionStorage if you prefer
    }

    const pidx = params.get("pidx");
    const status = params.get("status");
    const transactionId = params.get("transaction_id");
    const amount = params.get("amount");
    const mobile = params.get("mobile");
    const purchaseOrderId = params.get("purchase_order_id");
    const purchaseOrderName = params.get("purchase_order_name");
    const totalAmount = params.get("total_amount");

    console.log("Payment callback parameters:", Object.fromEntries(params.entries()));

    setLoading(true);
    setError(null);

    if (status === "Completed") {
      setPaymentStatus("Payment was successful");
      verifyPayment(transactionId);
      window.location.href = "/student-courses";
    } else if (status === "User canceled") {
      setPaymentStatus("Payment was canceled by the user");
      setLoading(false);
    } else if (status === "Pending") {
      performLookup(pidx);
    } else {
      setPaymentStatus("Unknown payment status");
      setLoading(false);
    }
  }, []);

  const verifyPayment = async (transactionId) => {
    try {
      const accessToken = JSON.parse(localStorage.getItem("accessToken")) || "";

      const response = await axios.post(
        "https://localhost:443/student/order/verify-payment",
        { transactionId },
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (response.status === 200) {
        setPaymentStatus("Payment verified successfully");
      } else {
        setPaymentStatus("Payment verification failed");
      }
      setLoading(false);
    } catch (error) {
      console.error("Error during payment verification:", error);
      setError(
        error.response?.data?.message ||
          "An error occurred while verifying payment"
      );
      setLoading(false);
    }
  };

  const performLookup = async (pidx) => {
    try {
      const response = await axios.post(
        "https://khalti.com/api/epayment/lookup/",
        { pidx },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );

      const lookupData = response.data;
      if (lookupData.status === "Completed") {
        setPaymentStatus("Payment was successfully completed after lookup");
      } else if (lookupData.status === "Pending") {
        setPaymentStatus("Payment is still pending");
      } else if (lookupData.status === "Refunded") {
        setPaymentStatus("Payment was refunded");
      } else if (lookupData.status === "User canceled") {
        setPaymentStatus("Payment was canceled by user");
      } else {
        setPaymentStatus("Unknown payment status");
      }
    } catch (error) {
      console.error("Error during lookup:", error);
      setError(
        error.response?.data?.message ||
          "An error occurred while checking payment status"
      );
      setLoading(false);
    }
  };

  return (
    <div>
      <h1>Payment Status</h1>
      {loading ? (
        <p>Loading...</p>
      ) : error ? (
        <p>{error}</p>
      ) : (
        <p>{paymentStatus}</p>
      )}
    </div>
  );
};

export default PaymentReturnPage;
