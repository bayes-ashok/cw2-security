import mongoose from 'mongoose';


const connectDB = async () => {
  try {
    await mongoose.connect("mongodb://localhost:27017/sikshyalaya", {
    });
    console.log("Connected to MongoDB");
  } catch (e) {
    console.error("MongoDB connection error:", e.message);
  }
};

export default connectDB;
