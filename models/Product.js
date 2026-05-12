import mongoose from "mongoose";

const productSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    price: {
      type: Number,
      default: 0,
    },

    supplier: {
      type: String,
      default: "",
    },

    supplierSlug: {
      type: String,
      default: "",
    },

    category: {
      type: String,
      default: "",
    },

    categorySlug: {
      type: String,
      default: "",
    },

    brand: {
      type: String,
      default: "",
    },

    manufacturer: {
      type: String,
      default: "",
    },

    capacity: {
      type: String,
      default: "",
    },

    description: {
      type: String,
      default: "",
    },

    image: {
      type: String,
      default: "",
    },

    images: {
      type: [String],
      default: [],
    },

    features: {
      type: [String],
      default: [],
    },

    specifications: {
      type: Object,
      default: {},
    },
    reviews: [
  {
    name: String,
    email: String,
    rating: Number,
    comment: String,
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
    ],

    averageRating: {
      type: Number,
      default: 0,
    },

    reviewCount: {
      type: Number,
      default: 0,
    },
    inStock: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
  }
);

const Product = mongoose.model("Product", productSchema);

export default Product;