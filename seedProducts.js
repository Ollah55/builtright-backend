import mongoose from "mongoose";
import dotenv from "dotenv";
import Product from "./models/Product.js";
import products from "./data/products.js";

dotenv.config();

const seedProducts = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);

    console.log("MongoDB connected...");

    // Clear old products
    await Product.deleteMany();
    console.log("Old products removed");

    // Insert new products
    await Product.insertMany(products);
    console.log("New products inserted successfully");

    process.exit();
  } catch (error) {
    console.error("SEED ERROR:", error);
    process.exit(1);
  }
};

seedProducts();