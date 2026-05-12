import mongoose from "mongoose";

const orderItemSchema = new mongoose.Schema(
  {
    id: { type: String, default: "" },
    name: { type: String, default: "Selected Product" },
    quantity: { type: Number, default: 1 },
    price: { type: Number, default: null },
    supplier: { type: String, default: "" },
    manufacturer: { type: String, default: "" },
    category: { type: String, default: "" },
    type: { type: String, default: "" },
    capacity: { type: String, default: "" },
    image: { type: String, default: "" },
  },
  { _id: false }
);

const orderSchema = new mongoose.Schema(
  {
    orderNumber: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },

    reference: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },

    source: {
      type: String,
      enum: ["Paystack", "Financing", "Manual"],
      default: "Paystack",
    },

    customer: {
      fullName: { type: String, required: true, trim: true },
      email: { type: String, required: true, trim: true, lowercase: true },
      phone: { type: String, required: true, trim: true },
    },

    items: {
      type: [orderItemSchema],
      default: [],
    },

    amount: {
      type: Number,
      default: null,
    },

    date: {
      type: String,
      required: true,
    },

    status: {
      type: String,
      enum: [
        "Paid",
        "Financing Approved",
        "Processing",
        "Confirmed",
        "Delivered",
        "Cancelled",
        "Refunded",
      ],
      default: "Paid",
    },

    financingRequestId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "LoanRequest",
      default: null,
    },
  },
  { timestamps: true }
);

const Order = mongoose.model("Order", orderSchema);

export default Order;