/* eslint-env node */
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import axios from "axios";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";

import Product from "./models/Product.js";
import Order from "./models/Order.js";
import LoanRequest from "./models/LoanRequest.js";
import User from "./models/User.js";
import sendEmail from "./utils/sendEmail.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({
  storage: multer.memoryStorage(),
});

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((error) => console.error("MongoDB connection error:", error.message));

const createToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
};

const requireAdminAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        status: false,
        message: "Unauthorized",
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "admin") {
      return res.status(403).json({
        status: false,
        message: "Admin access required.",
      });
    }

    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      status: false,
      message: "Invalid or expired token.",
    });
  }
};

const requireCustomerAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        status: false,
        message: "Unauthorized",
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      status: false,
      message: "Invalid or expired token.",
    });
  }
};

const generateOrderNumber = () => {
  const now = new Date();
  const datePart = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(
    2,
    "0"
  )}${String(now.getDate()).padStart(2, "0")}`;
  const timePart = now.getTime().toString().slice(-4);

  return `BR-${datePart}-${timePart}`;
};

const formatCurrency = (value) => {
  if (value == null) return "Request Price";
  return `₦${Number(value).toLocaleString()}`;
};

const buildReceiptHtml = (order) => {
  const itemsHtml =
    order.items
      ?.map(
        (item) => `
          <tr>
            <td style="padding:10px;border-bottom:1px solid #eee;">${item.name}</td>
            <td style="padding:10px;border-bottom:1px solid #eee;">${item.quantity || 1}</td>
            <td style="padding:10px;border-bottom:1px solid #eee;">${formatCurrency(item.price)}</td>
            <td style="padding:10px;border-bottom:1px solid #eee;">
              ${
                item.price != null
                  ? formatCurrency(Number(item.price) * Number(item.quantity || 1))
                  : "Request Price"
              }
            </td>
          </tr>
        `
      )
      .join("") || "";

  return `
    <div style="font-family:Arial,sans-serif;color:#222;line-height:1.6;max-width:700px;margin:0 auto;">
      <h2>BuiltRight Services Ltd</h2>
      <h3 style="color:#c62828;">Payment Receipt</h3>

      <p>Hello ${order.customer?.fullName || "Customer"},</p>
      <p>Thank you for your payment. Your order has been received successfully.</p>

      <div style="background:#f7f7f7;padding:16px;border-radius:10px;margin:16px 0;">
        <p><strong>Order Number:</strong> ${order.orderNumber}</p>
        <p><strong>Payment Reference:</strong> ${order.reference}</p>
        <p><strong>Payment Date:</strong> ${order.date}</p>
        <p><strong>Total Paid:</strong> ${formatCurrency(order.amount)}</p>
      </div>

      <h4>Order Summary</h4>

      <table style="width:100%;border-collapse:collapse;">
        <thead>
          <tr style="background:#fafafa;">
            <th style="padding:10px;text-align:left;border-bottom:1px solid #eee;">Product</th>
            <th style="padding:10px;text-align:left;border-bottom:1px solid #eee;">Qty</th>
            <th style="padding:10px;text-align:left;border-bottom:1px solid #eee;">Unit Price</th>
            <th style="padding:10px;text-align:left;border-bottom:1px solid #eee;">Total</th>
          </tr>
        </thead>
        <tbody>${itemsHtml}</tbody>
      </table>

      <div style="margin-top:20px;background:#f9fafb;padding:16px;border-radius:10px;">
        <h4 style="margin-top:0;">Next Step</h4>
        <p>Our team will contact you shortly to confirm delivery or installation schedule.</p>
      </div>

      <p style="margin-top:20px;">
        For urgent enquiries, call <strong>+234 913 499 1239</strong>.
      </p>
    </div>
  `;
};
const getBankEmail = (financeInstitution) => {
  const bankEmails = {
    "Rich Green Microfinance Bank":
      "builtrightenergy@gmail.com",

    "Premium Trust Bank":
      "builtrightenergy@gmail.com",

    "Zenith Bank":
      "builtrightenergy@gmail.com",
  };

  return (
    bankEmails[financeInstitution] ||
    "builtrightenergy@gmail.com"
  );
};

/* =========================
   BASIC
========================= */

app.get("/", (req, res) => {
  res.send("Backend is running");
});

/* =========================
   PRODUCTS
========================= */

app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });

    return res.json({
      status: true,
      products,
    });
  } catch (error) {
    console.error("GET PRODUCTS ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to fetch products.",
    });
  }
});

app.post("/api/admin/products", requireAdminAuth, async (req, res) => {
  try {
    const incomingImages = Array.isArray(req.body.images)
      ? req.body.images
      : [];

    const mainImage = req.body.image || incomingImages[0] || "";

    const product = await Product.create({
      ...req.body,
      image: mainImage,
      images: incomingImages.length > 0 ? incomingImages : mainImage ? [mainImage] : [],
    });

    return res.status(201).json({
      status: true,
      message: "Product created successfully.",
      product,
    });
  } catch (error) {
    console.error("CREATE PRODUCT ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to create product.",
    });
  }
});
app.patch("/api/admin/products/:id", requireAdminAuth, async (req, res) => {
  try {
    const incomingImages = Array.isArray(req.body.images)
      ? req.body.images
      : [];

    const mainImage = req.body.image || incomingImages[0] || "";

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      {
        ...req.body,
        image: mainImage,
        images: incomingImages.length > 0 ? incomingImages : mainImage ? [mainImage] : [],
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!product) {
      return res.status(404).json({
        status: false,
        message: "Product not found.",
      });
    }

    return res.json({
      status: true,
      message: "Product updated successfully.",
      product,
    });
  } catch (error) {
    console.error("UPDATE PRODUCT ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to update product.",
    });
  }
});
app.delete("/api/admin/products/:id", requireAdminAuth, async (req, res) => {
  try {
    const deletedProduct = await Product.findByIdAndDelete(req.params.id);

    if (!deletedProduct) {
      return res.status(404).json({
        status: false,
        message: "Product not found.",
      });
    }

    return res.json({
      status: true,
      message: "Product deleted successfully.",
    });
  } catch (error) {
    console.error("DELETE PRODUCT ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to delete product.",
    });
  }
});

/* =========================
   ADMIN AUTH
========================= */

app.post("/api/admin/login", (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      email !== process.env.ADMIN_EMAIL ||
      password !== process.env.ADMIN_PASSWORD
    ) {
      return res.status(401).json({
        status: false,
        message: "Invalid admin credentials.",
      });
    }

    const token = createToken({
      email,
      role: "admin",
    });

    return res.json({
      status: true,
      message: "Login successful.",
      token,
    });
  } catch (error) {
    console.error("ADMIN LOGIN ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Admin login failed.",
    });
  }
});

/* =========================
   CUSTOMER AUTH
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, phone, location, password } = req.body;

    if (!fullName || !email || !phone || !password) {
      return res.status(400).json({
        status: false,
        message: "Full name, email, phone, and password are required.",
      });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });

    if (existingUser) {
      return res.status(409).json({
        status: false,
        message: "An account with this email already exists.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      fullName,
      email: email.toLowerCase(),
      phone,
      location: location || "",
      password: hashedPassword,
      role: "customer",
    });

    const token = createToken({
      id: user._id,
      email: user.email,
      role: user.role,
    });

    return res.status(201).json({
      status: true,
      message: "Account created successfully.",
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        location: user.location,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Registration failed.",
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: false,
        message: "Email and password are required.",
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(401).json({
        status: false,
        message: "Invalid email or password.",
      });
    }

    const passwordMatches = await bcrypt.compare(password, user.password);

    if (!passwordMatches) {
      return res.status(401).json({
        status: false,
        message: "Invalid email or password.",
      });
    }

    const token = createToken({
      id: user._id,
      email: user.email,
      role: user.role,
    });

    return res.json({
      status: true,
      message: "Login successful.",
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        location: user.location,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Login failed.",
    });
  }
});

/* =========================
   PAYSTACK
========================= */

app.post("/api/paystack/initialize", async (req, res) => {
  try {
    const { email, amount, fullName, phone, cartItems } = req.body;

    if (!email || !fullName || !phone || !Array.isArray(cartItems)) {
      return res.status(400).json({
        status: false,
        message: "Missing required payment fields.",
      });
    }

    if (amount == null || Number(amount) <= 0) {
      return res.status(400).json({
        status: false,
        message: "Invalid payment amount.",
      });
    }

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email,
        amount: Number(amount) * 100,
        metadata: {
          fullName,
          phone,
          items: cartItems,
        },
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    return res.json(response.data);
  } catch (error) {
    console.error("PAYSTACK INIT ERROR:", error?.response?.data || error.message);

    return res.status(500).json({
      status: false,
      message: "Payment initialization failed.",
    });
  }
});

app.get("/api/paystack/verify/:reference", async (req, res) => {
  try {
    const { reference } = req.params;

    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    return res.json(response.data);
  } catch (error) {
    console.error("PAYSTACK VERIFY ERROR:", error?.response?.data || error.message);

    return res.status(500).json({
      status: false,
      message: "Payment verification failed.",
    });
  }
});

/* =========================
   ORDERS
========================= */

app.post("/api/orders/finalize", async (req, res) => {
  try {
    const { reference, customer, amount, cartItems } = req.body;

    if (!reference || !customer || !Array.isArray(cartItems)) {
      return res.status(400).json({
        status: false,
        message: "Missing required order fields.",
      });
    }

    const verifyResponse = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    const verifyData = verifyResponse.data;

    if (!verifyData.status || verifyData.data?.status !== "success") {
      return res.status(400).json({
        status: false,
        message: "Payment not verified.",
      });
    }

    const existingOrder = await Order.findOne({ reference });

    if (existingOrder) {
      return res.json({
        status: true,
        message: "Order already finalized.",
        order: existingOrder,
      });
    }

    const order = await Order.create({
      orderNumber: generateOrderNumber(),
      reference,
      customer: {
        fullName: customer.fullName,
        email: customer.email,
        phone: customer.phone,
      },
      items: cartItems,
      amount: amount ?? null,
      date: new Date().toLocaleDateString(),
      status: "Paid",
    });

    try {
      await sendEmail({
        to: order.customer.email,
        subject: `BuiltRight Payment Receipt - ${order.orderNumber}`,
        html: buildReceiptHtml(order),
      });
    } catch (mailError) {
      console.error("ORDER RECEIPT EMAIL ERROR:", mailError.message);
    }

    return res.json({
      status: true,
      message: "Order finalized successfully.",
      order,
    });
  } catch (error) {
    console.error("FINALIZE ORDER ERROR:", error?.response?.data || error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to finalize order.",
    });
  }
});

app.get("/api/orders/:reference", async (req, res) => {
  try {
    const order = await Order.findOne({ reference: req.params.reference });

    if (!order) {
      return res.status(404).json({
        status: false,
        message: "Order not found.",
      });
    }

    return res.json({
      status: true,
      order,
    });
  } catch (error) {
    console.error("GET ORDER ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to load order.",
    });
  }
});

app.get("/api/admin/orders", requireAdminAuth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });

    return res.json({
      status: true,
      orders,
    });
  } catch (error) {
    console.error("GET ADMIN ORDERS ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to load orders.",
    });
  }
});

app.patch("/api/admin/orders/:id/status", requireAdminAuth, async (req, res) => {
  try {
    const { status } = req.body;

    const allowedStatuses = [
      "Paid",
      "Processing",
      "Confirmed",
      "Delivered",
      "Cancelled",
      "Refunded",
    ];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        status: false,
        message: "Invalid order status.",
      });
    }

    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    if (!order) {
      return res.status(404).json({
        status: false,
        message: "Order not found.",
      });
    }

    try {
      await sendEmail({
        to: order.customer?.email,
        subject: "BuiltRight Order Status Update",
        html: `
          <h2>Order Status Updated</h2>
          <p>Hello ${order.customer?.fullName || "Customer"},</p>
          <p>Your order status is now:</p>
          <h3>${order.status}</h3>
          <p>Thank you for choosing BuiltRight Services Ltd.</p>
        `,
      });
    } catch (mailError) {
      console.error("ORDER STATUS EMAIL ERROR:", mailError.message);
    }

    return res.json({
      status: true,
      message: "Order status updated.",
      order,
    });
  } catch (error) {
    console.error("UPDATE ORDER STATUS ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to update order status.",
    });
  }
});

/* =========================
   LOAN / FINANCING REQUESTS
========================= */

app.post("/api/loan-request", async (req, res) => {
  try {
    const {
      customer,
      items,
      estimatedAmount,
      productSource,
      financeInstitution,
      interestRate,
      loanTenor,
      depositRequired,
      vendorName,
      vendorContact,
      vendorProductDetails,
      consentToShare,
      thirdPartyNoticeAccepted,
      notes,
    } = req.body;

    const selectedProductSource = productSource || "BuiltRight Marketplace";
    const selectedFinanceInstitution =
      financeInstitution || "Rich Green Microfinance Bank";

    if (!customer?.fullName || !customer?.email || !customer?.phone) {
      return res.status(400).json({
        status: false,
        message: "Missing required customer fields.",
      });
    }

    if (!consentToShare) {
      return res.status(400).json({
        status: false,
        message: "Customer consent is required.",
      });
    }

    if (selectedProductSource === "BuiltRight Marketplace") {
      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({
          status: false,
          message: "Please select at least one BuiltRight marketplace product.",
        });
      }
    }

    if (selectedProductSource === "External Vendor") {
      if (!vendorName || !vendorContact || !vendorProductDetails) {
        return res.status(400).json({
          status: false,
          message: "Please provide external vendor details.",
        });
      }

      if (!thirdPartyNoticeAccepted) {
        return res.status(400).json({
          status: false,
          message: "Customer must accept the third-party product notice.",
        });
      }
    }

    const itemsToSave =
      selectedProductSource === "External Vendor"
        ? [
            {
              id: `external-${Date.now()}`,
              name: vendorProductDetails,
              quantity: 1,
              price: null,
              supplier: vendorName,
              manufacturer: "External Vendor",
              category: "external-solar-system",
              type: "Third-Party Solar System",
              capacity: "",
            },
          ]
        : items;

    const loanRequest = await LoanRequest.create({
      customer: {
        fullName: customer.fullName,
        email: customer.email,
        phone: customer.phone,
      },
      productSource: selectedProductSource,
      financeInstitution: selectedFinanceInstitution,
      interestRate: interestRate || "",
      loanTenor: loanTenor || "",
      depositRequired: depositRequired || "",
      vendorName: vendorName || "",
      vendorContact: vendorContact || "",
      vendorProductDetails: vendorProductDetails || "",
      items: itemsToSave,
      estimatedAmount: estimatedAmount ?? null,
      consentToShare: Boolean(consentToShare),
      thirdPartyNoticeAccepted: Boolean(thirdPartyNoticeAccepted),
      preferredContact: "WhatsApp",
      status: "pending",
      notes: notes || "",
    });

    try {
      await sendEmail({
        to: process.env.ADMIN_ALERT_EMAIL || process.env.SMTP_USER,
        subject: `New Financing Request - ${customer.fullName}`,
        html: `
          <h2>New Financing Request</h2>
          <p><strong>Name:</strong> ${customer.fullName}</p>
          <p><strong>Email:</strong> ${customer.email}</p>
          <p><strong>Phone:</strong> ${customer.phone}</p>
          <p><strong>Product Source:</strong> ${selectedProductSource}</p>
          <p><strong>Finance Institution:</strong> ${selectedFinanceInstitution}</p>
          <p><strong>Status:</strong> pending</p>
        `,
      });
    } catch (mailError) {
      console.error("ADMIN FINANCING EMAIL ERROR:", mailError.message);
    }

    // Email disabled during local testing.
    // Re-enable after SMTP is confirmed working.

    return res.json({
      status: true,
      message: "Loan request submitted successfully.",
      loanRequest,
    });
  } catch (error) {
    console.error("LOAN REQUEST ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to submit loan request.",
    });
  }
});

app.get("/api/loan-requests", requireAdminAuth, async (req, res) => {
  try {
    const loanRequests = await LoanRequest.find().sort({ createdAt: -1 });

    return res.json({
      status: true,
      loanRequests,
    });
  } catch (error) {
    console.error("GET LOAN REQUESTS ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to load loan requests.",
    });
  }
});
app.delete("/api/loan-requests/:id", requireAdminAuth, async (req, res) => {
  try {
    const deletedLoanRequest = await LoanRequest.findByIdAndDelete(req.params.id);

    if (!deletedLoanRequest) {
      return res.status(404).json({
        status: false,
        message: "Loan request not found.",
      });
    }

    return res.json({
      status: true,
      message: "Loan request deleted successfully.",
    });
  } catch (error) {
    console.error("DELETE LOAN REQUEST ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to delete loan request.",
    });
  }
});
app.patch("/api/loan-requests/:id/status", requireAdminAuth, async (req, res) => {
  try {
    const { status } = req.body;

    const allowedStatuses = [
      "pending",
      "contacted",
      "sent-to-bank",
      "under-assessment",
      "approved",
      "declined",
      "installation-scheduled",
      "completed",
    ];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        status: false,
        message: "Invalid status value.",
      });
    }

    const loanRequest = await LoanRequest.findById(req.params.id);

    if (!loanRequest) {
      return res.status(404).json({
        status: false,
        message: "Loan request not found.",
      });
    }

    let createdOrder = null;

    if (status === "approved") {
      const financingReference = `LOAN-${loanRequest._id}`;

      const existingOrder = await Order.findOne({
        reference: financingReference,
      });

      const safeItems =
        Array.isArray(loanRequest.items) && loanRequest.items.length > 0
          ? loanRequest.items.map((item) => ({
              id: item.id || item._id?.toString() || "",
              name:
                item.name ||
                item.productName ||
                item.title ||
                item.description ||
                item.vendorProductDetails ||
                item.capacity ||
                "Selected Product",
              quantity: Number(item.quantity || 1),
              price: item.price == null ? null : Number(item.price),
              supplier: item.supplier || "",
              manufacturer: item.manufacturer || "",
              category: item.category || "",
              type: item.type || "",
              capacity: item.capacity || "",
              image: item.image || "",
            }))
          : [
              {
                id: "",
                name: "Selected Product",
                quantity: 1,
                price: loanRequest.estimatedAmount ?? null,
                supplier: "",
                manufacturer: "",
                category: "",
                type: "",
                capacity: "",
                image: "",
              },
            ];

      if (!existingOrder) {
        createdOrder = await Order.create({
          orderNumber: generateOrderNumber(),
          reference: financingReference,
          source: "Financing",

          customer: {
            fullName: loanRequest.customer.fullName,
            email: loanRequest.customer.email,
            phone: loanRequest.customer.phone,
          },

          items: safeItems,
          amount: loanRequest.estimatedAmount ?? null,
          date: new Date().toLocaleDateString(),
          status: "Financing Approved",
          financingRequestId: loanRequest._id,
        });
      } else {
        createdOrder = existingOrder;
      }
    }

    loanRequest.status = status;
    await loanRequest.save();

    try {
  const statusMessages = {
    pending: {
      title: "Financing Request Received",
      message:
        "Your financing request has been received and is awaiting review.",
    },

    contacted: {
      title: "BuiltRight Contacted You",
      message:
        "Our team has reviewed your request and will contact you shortly.",
    },

    "sent-to-bank": {
      title: "Request Sent to Financing Institution",
      message:
        "Your financing request has been forwarded to the selected financing institution for review.",
    },

    "under-assessment": {
      title: "Financing Assessment Ongoing",
      message:
        "Your financing request is currently undergoing assessment and eligibility review.",
    },

    approved: {
      title: "Financing Approved",
      message:
        "Congratulations. Your financing request has been approved successfully.",
    },

    "installation-scheduled": {
      title: "Installation Scheduled",
      message:
        "Your installation process has been scheduled. BuiltRight will contact you with installation details shortly.",
    },

    completed: {
      title: "Project Completed",
      message:
        "Your financing and installation process has been completed successfully.",
    },

    declined: {
      title: "Financing Request Declined",
      message:
        "Unfortunately, your financing request was not approved at this time.",
    },
  };

  const currentStatus =
    statusMessages[status] || statusMessages.pending;

  await sendEmail({
    to: loanRequest.customer.email,

    subject: `BuiltRight Financing Update - ${currentStatus.title}`,

    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.7;color:#222;">
        <h2>${currentStatus.title}</h2>

        <p>
          Hello ${loanRequest.customer.fullName},
        </p>

        <p>
          ${currentStatus.message}
        </p>

        <div style="background:#f5f5f5;padding:15px;border-radius:10px;margin:20px 0;">
          <p>
            <strong>Current Status:</strong>
            ${status}
          </p>

          <p>
            <strong>Financing Institution:</strong>
            ${loanRequest.financeInstitution}
          </p>

          <p>
            <strong>Estimated Amount:</strong>
            ${
              loanRequest.estimatedAmount
                ? formatCurrency(loanRequest.estimatedAmount)
                : "Request Price"
            }
          </p>
        </div>

        <p>
          Thank you for choosing BuiltRight Services Ltd.
        </p>
      </div>
    `,
  });

  console.log(
    "CUSTOMER STATUS EMAIL SENT TO:",
    loanRequest.customer.email
  );
} catch (mailError) {
  console.error(
    "CUSTOMER FINANCING STATUS EMAIL ERROR:",
    mailError.message
  );
}

    if (status === "sent-to-bank") {
  try {
    const bankEmail = getBankEmail(loanRequest.financeInstitution);

    await sendEmail({
      to: bankEmail,
      subject: `BuiltRight Financing Request - ${loanRequest.customer.fullName}`,
      html: `
        <h2>BuiltRight Financing Request</h2>

        <p><strong>Customer:</strong> ${loanRequest.customer.fullName}</p>
        <p><strong>Email:</strong> ${loanRequest.customer.email}</p>
        <p><strong>Phone:</strong> ${loanRequest.customer.phone}</p>

        <p><strong>Finance Institution:</strong> ${loanRequest.financeInstitution}</p>
        <p><strong>Product Source:</strong> ${loanRequest.productSource}</p>
        <p><strong>Estimated Amount:</strong> ${formatCurrency(loanRequest.estimatedAmount)}</p>

        <h3>Requested Items</h3>
        <ul>
          ${(loanRequest.items || [])
            .map(
              (item) =>
                `<li>${item.name || "Selected Product"} - ${
                  item.price != null ? formatCurrency(item.price) : "Request Price"
                }</li>`
            )
            .join("")}
        </ul>

        <h3>Notes</h3>
        <p>${loanRequest.notes || "No notes provided."}</p>
      `,
    });

    console.log("BANK EMAIL SENT TO:", bankEmail);
  } catch (mailError) {
    console.error("BANK EMAIL ERROR:", mailError.message);
  }
}

    return res.json({
      status: true,
      message:
        status === "approved"
          ? "Loan request approved and order created."
          : "Loan request status updated.",
      loanRequest,
      order: createdOrder,
    });
  } catch (error) {
    console.error("UPDATE LOAN REQUEST STATUS ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: error.message || "Failed to update loan request status.",
    });
  }
});

/* =========================
   ADMIN DASHBOARD
========================= */

app.get("/api/admin/dashboard-stats", requireAdminAuth, async (req, res) => {
  try {
    const totalProducts = await Product.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalLoanRequests = await LoanRequest.countDocuments();
    const totalCustomers = await User.countDocuments({ role: "customer" });
    const pendingLoanRequests = await LoanRequest.countDocuments({
      status: "pending",
    });
    const approvedLoans = await LoanRequest.countDocuments({
      status: "approved",
    });

    return res.json({
      status: true,
      stats: {
        totalProducts,
        totalOrders,
        totalLoanRequests,
        totalCustomers,
        pendingLoanRequests,
        approvedLoans,
      },
    });
  } catch (error) {
    console.error("DASHBOARD STATS ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to load dashboard stats.",
    });
  }
});

app.get("/api/admin/customers", requireAdminAuth, async (req, res) => {
  try {
    const customers = await User.find({ role: "customer" })
      .select("-password")
      .sort({ createdAt: -1 });

    return res.json({
      status: true,
      customers,
    });
  } catch (error) {
    console.error("GET CUSTOMERS ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to load customers.",
    });
  }
});
app.delete("/api/admin/customers/:id", requireAdminAuth, async (req, res) => {
  try {
    const deletedCustomer = await User.findOneAndDelete({
      _id: req.params.id,
      role: "customer",
    });

    if (!deletedCustomer) {
      return res.status(404).json({
        status: false,
        message: "Customer not found.",
      });
    }

    return res.json({
      status: true,
      message: "Customer deleted successfully.",
    });
  } catch (error) {
    console.error("DELETE CUSTOMER ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to delete customer.",
    });
  }
});

/* =========================
   CUSTOMER DASHBOARD
========================= */

app.get("/api/customer/loan-requests", requireCustomerAuth, async (req, res) => {
  try {
    const loanRequests = await LoanRequest.find({
      "customer.email": req.user.email,
    }).sort({ createdAt: -1 });

    return res.json({
      status: true,
      loanRequests,
    });
  } catch (error) {
    console.error("CUSTOMER LOAN REQUESTS ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to load financing requests.",
    });
  }
});

app.get("/api/customer/orders", requireCustomerAuth, async (req, res) => {
  try {
    const orders = await Order.find({
      "customer.email": req.user.email,
    }).sort({ createdAt: -1 });

    return res.json({
      status: true,
      orders,
    });
  } catch (error) {
    console.error("CUSTOMER ORDERS ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to load orders.",
    });
  }
});

app.patch("/api/customer/profile", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        status: false,
        message: "Unauthorized",
      });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { fullName, phone, location } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      decoded.id,
      {
        fullName,
        phone,
        location,
      },
      {
        new: true,
      }
    ).select("-password");

    if (!updatedUser) {
      return res.status(404).json({
        status: false,
        message: "User not found.",
      });
    }

    return res.json({
      status: true,
      message: "Profile updated successfully.",
      user: updatedUser,
    });
  } catch (error) {
    console.error("UPDATE PROFILE ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Failed to update profile.",
    });
  }
});
app.get("/api/test", (req, res) => {
  res.json({
    status: true,
    message: "API WORKS",
  });
});
app.post(
  "/api/admin/upload-image",
  requireAdminAuth,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          status: false,
          message: "No image uploaded.",
        });
      }

      const fileBase64 = req.file.buffer.toString("base64");
      const fileUri = `data:${req.file.mimetype};base64,${fileBase64}`;

      const result = await cloudinary.uploader.upload(fileUri, {
        folder: "builtright-products",
      });

      return res.json({
        status: true,
        message: "Image uploaded successfully.",
        imageUrl: result.secure_url,
      });
    } catch (error) {
      console.error("IMAGE UPLOAD ERROR:", error.message);

      return res.status(500).json({
        status: false,
        message: "Failed to upload image.",
      });
    }
  }
);
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});