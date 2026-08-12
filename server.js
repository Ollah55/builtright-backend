/* eslint-env node */
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import axios from "axios";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { jsPDF } from "jspdf";

import Product from "./models/Product.js";
import Order from "./models/Order.js";
import LoanRequest from "./models/LoanRequest.js";
import User from "./models/User.js";
import Device from "./models/Device.js";
import DeviceAlert from "./models/DeviceAlert.js";
import DeviceCommand from "./models/DeviceCommand.js";
import ProjectDocument from "./models/ProjectDocument.js";
import sendEmail from "./utils/sendEmail.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());

// Provider webhook routes keep the raw request body available for future
// HMAC verification. They remain closed until each provider specification and
// secret has been configured.
app.post(
  "/api/webhooks/bank/:provider",
  express.raw({ type: "application/json" }),
  (req, res) =>
    res.status(503).json({
      status: false,
      code: "BANK_PROVIDER_NOT_CONFIGURED",
      message: "Bank webhook processing is not configured.",
    })
);

app.post(
  "/api/webhooks/ashgridx",
  express.raw({ type: "application/json" }),
  (req, res) =>
    res.status(503).json({
      status: false,
      code: "ASHGRIDX_NOT_CONFIGURED",
      message: "AshGridX webhook processing is not configured.",
    })
);

app.use(express.json());

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({
  storage: multer.memoryStorage(),
});

const createToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
};

const frontendUrl = () => process.env.FRONTEND_URL || "https://www.builtrightltd.com";

const inspectionPaymentDetails = {
  bank: process.env.INSPECTION_PAYMENT_BANK || "FCMB",
  accountNumber: process.env.INSPECTION_PAYMENT_ACCOUNT || "2008839924",
  accountName: process.env.INSPECTION_PAYMENT_ACCOUNT_NAME || "BuiltRight Services Ltd",
};

const initialInstallers = [
  { fullName: "Mr Taiwo Olanrewaju", email: "taiwo.olanrewaju@builtrightltd.com" },
  { fullName: "Ms Anita Agary", email: "anita.agary@builtrightltd.com" },
];

const safeHtml = (value = "") => String(value)
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#039;");

const formatNaira = (amount) => `₦${Number(amount || 0).toLocaleString("en-NG", { maximumFractionDigits: 0 })}`;

const sendInstallerInviteEmail = async (user, rawToken) => {
  const activationUrl = `${frontendUrl()}/installer/activate?token=${rawToken}`;
  try {
    await sendEmail({
      to: user.email,
      subject: "Welcome to BuiltRight Installer Operations",
      html: `<h2>Welcome to BuiltRight</h2><p>Hello ${safeHtml(user.fullName)},</p><p>Your installer account is ready. Set a secure password to access your assignments, schedule inspections, complete load audits, and submit installation-material requirements.</p><p><a href="${activationUrl}">Activate your installer account</a></p><p>This secure invitation expires in 7 days.</p>`,
    });
    user.installerProfile.invitationEmailSentAt = new Date();
    await user.save();
    return true;
  } catch (mailError) {
    console.error("INSTALLER INVITE EMAIL ERROR:", mailError.message);
    return false;
  }
};

const makeInstallerInvite = async (installer) => {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const temporaryPassword = crypto.randomBytes(24).toString("base64url");
  const user = await User.create({
    fullName: installer.fullName,
    email: installer.email,
    phone: "",
    password: await bcrypt.hash(temporaryPassword, 10),
    role: "installer",
    isActive: false,
    installerProfile: {
      availability: "available",
      invitationToken: rawToken,
      invitationExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      invitedAt: new Date(),
    },
  });
  await sendInstallerInviteEmail(user, rawToken);
  return user;
};

const reissueInstallerInviteForDomain = async (user) => {
  const rawToken = crypto.randomBytes(32).toString("hex");
  user.installerProfile.invitationToken = rawToken;
  user.installerProfile.invitationExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  user.installerProfile.invitedAt = new Date();
  user.installerProfile.invitationEmailSentAt = null;
  await user.save();
  if (await sendInstallerInviteEmail(user, rawToken)) {
    user.installerProfile.domainLinkReissuedAt = new Date();
    user.installerProfile.domainLinkReissueVersion = "custom-domain-v2";
    await user.save();
  }
};

const provisionInitialInstallers = async () => {
  for (const installer of initialInstallers) {
    const existing = await User.findOne({ email: installer.email });
    if (!existing) {
      await makeInstallerInvite(installer);
    } else if (
      existing.role === "installer" &&
      existing.installerProfile?.domainLinkReissueVersion !== "custom-domain-v2"
    ) {
      await reissueInstallerInviteForDomain(existing);
    } else if (
      existing.role === "installer" &&
      !existing.isActive &&
      existing.installerProfile?.invitationToken &&
      existing.installerProfile?.invitationExpiresAt > new Date() &&
      !existing.installerProfile?.invitationEmailSentAt
    ) {
      await sendInstallerInviteEmail(existing, existing.installerProfile.invitationToken);
    }
  }
};

mongoose
  .connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("MongoDB connected");
    await provisionInitialInstallers();
  })
  .catch((error) => console.error("MongoDB connection error:", error.message));

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

    if (decoded.role !== "customer") {
      return res.status(403).json({ status: false, message: "Customer access required." });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      status: false,
      message: "Invalid or expired token.",
    });
  }
};

const requireInstallerAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ status: false, message: "Unauthorized" });
    }
    const decoded = jwt.verify(authHeader.split(" ")[1], process.env.JWT_SECRET);
    if (decoded.role !== "installer") {
      return res.status(403).json({ status: false, message: "Installer access required." });
    }
    req.installer = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ status: false, message: "Invalid or expired token." });
  }
};

const generateOperationsReference = (prefix) =>
  `${prefix}-${Date.now().toString(36).toUpperCase()}-${new mongoose.Types.ObjectId()
    .toString()
    .slice(-4)
    .toUpperCase()}`;

const escapeSearchText = (value = "") =>
  String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const bankProviderConfigured =
  process.env.BANK_PROVIDER_ENABLED === "true" &&
  Boolean(process.env.BANK_PROVIDER_NAME && process.env.BANK_PROVIDER_BASE_URL);

// Credentials can be stored now, but outbound AshGridX commands remain closed
// until the final tamper, acknowledgement, and signature rules are confirmed.
const ashGridCredentialsPresent = Boolean(
  process.env.ASHGRIDX_API_BASE_URL && process.env.ASHGRIDX_API_KEY
);
const ashGridAdapterReady = false;

app.get("/api/integrations/status", requireAdminAuth, (req, res) => {
  res.json({
    status: true,
    integrations: {
      bank: {
        configured: bankProviderConfigured,
        mode: bankProviderConfigured ? "sandbox" : "manual",
      },
      ashGridX: {
        configured: ashGridAdapterReady,
        credentialsPresent: ashGridCredentialsPresent,
        mode: "sandbox-placeholder",
      },
    },
  });
});

app.post(
  "/api/integrations/bank/applications",
  requireAdminAuth,
  (req, res) =>
    res.status(503).json({
      status: false,
      code: "BANK_PROVIDER_NOT_CONFIGURED",
      message:
        "The financing case can continue through manual bank handoff, but the provider API is not configured.",
    })
);

app.post(
  "/api/integrations/ashgridx/device/control",
  requireAdminAuth,
  handleDeviceControl
);

async function resolveDevice(identifier) {
  if (!identifier) return null;
  if (mongoose.isValidObjectId(identifier)) {
    const byId = await Device.findById(identifier);
    if (byId) return byId;
  }
  return Device.findOne({
    $or: [
      { reference: String(identifier).toUpperCase() },
      { providerDeviceId: String(identifier) },
    ],
  });
}

async function handleDeviceControl(req, res) {
  try {
    const identifier =
      req.params.id || req.body.deviceId || req.body.customerDeviceId;
    const action = req.body.action || req.body.control;
    const reason = String(req.body.reason || "").trim();
    const device = await resolveDevice(identifier);

    if (!device) {
      return res.status(404).json({ status: false, message: "Device not found." });
    }

    if (!["on", "off"].includes(action)) {
      return res.status(400).json({
        status: false,
        message: "Device action must be either on or off.",
      });
    }

    if (!reason) {
      return res.status(400).json({
        status: false,
        message: "A control reason is required for the audit trail.",
      });
    }

    const humanConfirmed = req.body.confirmation === device.reference;
    const policyFailures = [];
    const now = new Date();

    if (!humanConfirmed) {
      policyFailures.push(`Type ${device.reference} to confirm this device action.`);
    }

    if (device.connectivity !== "online") {
      policyFailures.push("Device connectivity must be online and verified.");
    }

    if (action === "off") {
      if (device.paymentStanding !== "default-eligible") {
        policyFailures.push("Customer default has not been marked eligible for disablement.");
      }
      if (!device.defaultVerifiedAt) {
        policyFailures.push("Customer default has not been independently verified.");
      }
      if (!device.gracePeriod?.endsAt || device.gracePeriod.endsAt > now) {
        policyFailures.push("The required 10-day grace period has not completed.");
      }
      if (!device.gracePeriod?.communicationsCompletedAt) {
        policyFailures.push("Required customer communications have not been completed.");
      }
    }

    if (action === "on" && !["current", "cleared"].includes(device.paymentStanding)) {
      policyFailures.push("Payment clearance must be recorded before activation.");
    }

    const policySnapshot = {
      paymentStanding: device.paymentStanding,
      gracePeriodEndsAt: device.gracePeriod?.endsAt || null,
      defaultVerifiedAt: device.defaultVerifiedAt,
      communicationsCompletedAt:
        device.gracePeriod?.communicationsCompletedAt || null,
      deviceConnectivity: device.connectivity,
      humanConfirmed,
    };

    if (policyFailures.length > 0) {
      const command = await DeviceCommand.create({
        reference: generateOperationsReference("BRCMD"),
        device: device._id,
        deviceReference: device.reference,
        action,
        status: "blocked",
        requestedBy: {
          id: req.admin?.id || "",
          email: req.admin?.email || "",
        },
        reason,
        policySnapshot,
        blockedReason: policyFailures.join(" "),
      });

      return res.status(409).json({
        status: false,
        code: "DEVICE_CONTROL_POLICY_BLOCKED",
        message: "Device action blocked by BuiltRight safety policy.",
        reasons: policyFailures,
        commandReference: command.reference,
      });
    }

    const command = await DeviceCommand.create({
      reference: generateOperationsReference("BRCMD"),
      device: device._id,
      deviceReference: device.reference,
      action,
      status: "blocked",
      requestedBy: {
        id: req.admin?.id || "",
        email: req.admin?.email || "",
      },
      reason,
      policySnapshot,
      blockedReason: ashGridCredentialsPresent
        ? "AshGridX adapter awaiting final acknowledgement and tamper rules."
        : "AshGridX staging credentials are not configured.",
    });

    return res.status(503).json({
      status: false,
      code: "ASHGRIDX_NOT_CONFIGURED",
      message:
        "No device command was sent. The safe provider adapter remains inactive.",
      commandReference: command.reference,
    });
  } catch (error) {
    console.error("Device control error:", error);
    return res.status(500).json({
      status: false,
      message: "Device control request could not be processed.",
    });
  }
}

app.get("/api/admin/devices", requireAdminAuth, async (req, res) => {
  try {
    const query = {};
    if (req.query.connectivity) query.connectivity = req.query.connectivity;
    if (req.query.paymentStanding) query.paymentStanding = req.query.paymentStanding;
    if (req.query.tamper === "true") query["tamper.status"] = { $ne: "clear" };

    if (req.query.search) {
      const search = new RegExp(escapeSearchText(req.query.search), "i");
      query.$or = [
        { reference: search },
        { providerDeviceId: search },
        { serialNumber: search },
        { projectReference: search },
        { "customerSnapshot.fullName": search },
        { "site.address": search },
      ];
    }

    const devices = await Device.find(query).sort({ updatedAt: -1 }).limit(250).lean();
    return res.json({ status: true, devices });
  } catch (error) {
    console.error("Fetch devices error:", error);
    return res.status(500).json({ status: false, message: "Could not load devices." });
  }
});

app.post("/api/admin/devices", requireAdminAuth, async (req, res) => {
  try {
    const {
      reference,
      providerDeviceId,
      serialNumber,
      label,
      customerId,
      customerSnapshot,
      financingRequestId,
      orderId,
      projectReference,
      site,
      installedAt,
    } = req.body;

    if (!reference) {
      return res.status(400).json({
        status: false,
        message: "A unique BuiltRight device reference is required.",
      });
    }

    let customer = null;
    if (customerId) {
      if (!mongoose.isValidObjectId(customerId)) {
        return res.status(400).json({ status: false, message: "Invalid customer ID." });
      }
      customer = await User.findById(customerId);
      if (!customer) {
        return res.status(404).json({ status: false, message: "Customer not found." });
      }
    }

    const device = await Device.create({
      reference,
      providerDeviceId: providerDeviceId || undefined,
      serialNumber,
      label,
      customer: customer?._id || null,
      customerSnapshot: customer
        ? {
            fullName: customer.fullName,
            email: customer.email,
            phone: customer.phone,
          }
        : customerSnapshot,
      financingRequest: financingRequestId || null,
      order: orderId || null,
      projectReference,
      site,
      installedAt: installedAt || null,
      assignmentStatus: customer || customerSnapshot?.fullName ? "assigned" : "unassigned",
    });

    return res.status(201).json({ status: true, device });
  } catch (error) {
    if (error?.code === 11000) {
      return res.status(409).json({
        status: false,
        message: "That BuiltRight or provider device ID is already registered.",
      });
    }
    console.error("Create device error:", error);
    return res.status(500).json({ status: false, message: "Could not register device." });
  }
});

app.patch("/api/admin/devices/:id", requireAdminAuth, async (req, res) => {
  try {
    const device = await resolveDevice(req.params.id);
    if (!device) {
      return res.status(404).json({ status: false, message: "Device not found." });
    }

    const allowedFields = [
      "providerDeviceId",
      "serialNumber",
      "label",
      "customerSnapshot",
      "financingRequest",
      "order",
      "projectReference",
      "site",
      "assignmentStatus",
      "connectivity",
      "inverterState",
      "lastSeenAt",
      "tamper",
      "paymentStanding",
      "defaultVerifiedAt",
      "gracePeriod",
      "installedAt",
      "metadata",
    ];

    allowedFields.forEach((field) => {
      if (Object.prototype.hasOwnProperty.call(req.body, field)) {
        device.set(field, req.body[field]);
      }
    });

    if (Object.prototype.hasOwnProperty.call(req.body, "customerId")) {
      if (req.body.customerId && !mongoose.isValidObjectId(req.body.customerId)) {
        return res.status(400).json({ status: false, message: "Invalid customer ID." });
      }
      const customer = req.body.customerId
        ? await User.findById(req.body.customerId)
        : null;
      if (req.body.customerId && !customer) {
        return res.status(404).json({ status: false, message: "Customer not found." });
      }
      device.customer = customer?._id || null;
      if (customer) {
        device.customerSnapshot = {
          fullName: customer.fullName,
          email: customer.email,
          phone: customer.phone,
        };
      }
    }

    await device.save();
    return res.json({ status: true, device });
  } catch (error) {
    console.error("Update device error:", error);
    return res.status(500).json({ status: false, message: "Could not update device." });
  }
});

app.post("/api/admin/devices/:id/control", requireAdminAuth, handleDeviceControl);

app.get("/api/admin/device-alerts", requireAdminAuth, async (req, res) => {
  try {
    const query = {};
    if (req.query.status) query.status = req.query.status;
    if (req.query.type) query.type = req.query.type;
    if (req.query.deviceId) {
      const device = await resolveDevice(req.query.deviceId);
      if (!device) return res.json({ status: true, alerts: [] });
      query.device = device._id;
    }
    const alerts = await DeviceAlert.find(query)
      .sort({ occurredAt: -1 })
      .limit(250)
      .lean();
    return res.json({ status: true, alerts });
  } catch (error) {
    console.error("Fetch device alerts error:", error);
    return res.status(500).json({ status: false, message: "Could not load device alerts." });
  }
});

app.patch("/api/admin/device-alerts/:id/status", requireAdminAuth, async (req, res) => {
  try {
    if (!["acknowledged", "resolved"].includes(req.body.status)) {
      return res.status(400).json({
        status: false,
        message: "Alert status must be acknowledged or resolved.",
      });
    }

    const alert = await DeviceAlert.findById(req.params.id);
    if (!alert) {
      return res.status(404).json({ status: false, message: "Alert not found." });
    }

    if (req.body.status === "acknowledged") {
      alert.status = "acknowledged";
      alert.acknowledgedAt = new Date();
      alert.acknowledgedBy = req.admin?.email || "BuiltRight admin";
    } else {
      alert.status = "resolved";
      alert.resolvedAt = new Date();
      alert.resolvedBy = req.admin?.email || "BuiltRight admin";
    }

    await alert.save();
    return res.json({ status: true, alert });
  } catch (error) {
    console.error("Update device alert error:", error);
    return res.status(500).json({ status: false, message: "Could not update alert." });
  }
});

app.get("/api/admin/device-commands", requireAdminAuth, async (req, res) => {
  try {
    const query = {};
    if (req.query.deviceId) {
      const device = await resolveDevice(req.query.deviceId);
      if (!device) return res.json({ status: true, commands: [] });
      query.device = device._id;
    }
    const commands = await DeviceCommand.find(query)
      .sort({ createdAt: -1 })
      .limit(250)
      .lean();
    return res.json({ status: true, commands });
  } catch (error) {
    console.error("Fetch device commands error:", error);
    return res.status(500).json({ status: false, message: "Could not load device commands." });
  }
});

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

const escapeHtml = (value = "") =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");

const formatDocumentMoney = (value) =>
  `NGN ${Number(value || 0).toLocaleString("en-NG")}`;

const buildProjectDocumentPdf = (projectDocument) => {
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const margin = 18;
  const usableWidth = 174;
  let y = 20;

  const ensureRoom = (height = 12) => {
    if (y + height > 278) {
      doc.addPage();
      y = 20;
    }
  };

  const writeWrapped = (text, x, width, lineHeight = 5) => {
    const lines = doc.splitTextToSize(String(text || ""), width);
    ensureRoom(lines.length * lineHeight + 2);
    doc.text(lines, x, y);
    y += lines.length * lineHeight;
  };

  doc.setFillColor(15, 79, 72);
  doc.rect(0, 0, 210, 38, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(19);
  doc.setFont("helvetica", "bold");
  doc.text("BuiltRight Services Ltd", margin, 18);
  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.text(
    projectDocument.type === "invoice" ? "PROJECT INVOICE" : "SOLAR PROJECT QUOTATION",
    margin,
    29
  );

  y = 49;
  doc.setTextColor(25, 36, 33);
  doc.setFontSize(10);
  doc.setFont("helvetica", "bold");
  doc.text(`Reference: ${projectDocument.reference}`, margin, y);
  doc.text(`Status: ${String(projectDocument.status).toUpperCase()}`, 125, y);
  y += 8;
  doc.setFont("helvetica", "normal");
  doc.text(`Customer: ${projectDocument.customer?.fullName || "Customer"}`, margin, y);
  doc.text(`Date: ${new Date(projectDocument.createdAt || Date.now()).toLocaleDateString("en-GB")}`, 125, y);
  y += 6;
  doc.text(`Email: ${projectDocument.customer?.email || ""}`, margin, y);
  if (projectDocument.validUntil) {
    doc.text(`Valid until: ${new Date(projectDocument.validUntil).toLocaleDateString("en-GB")}`, 125, y);
  }
  y += 11;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text(projectDocument.title || "Solar Project", margin, y);
  y += 7;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  writeWrapped(
    [
      projectDocument.project?.systemCapacity,
      projectDocument.project?.systemName,
      projectDocument.project?.siteAddress,
    ].filter(Boolean).join(" | "),
    margin,
    usableWidth
  );

  y += 4;
  doc.setFillColor(237, 246, 243);
  doc.rect(margin, y, usableWidth, 8, "F");
  doc.setFont("helvetica", "bold");
  doc.text("PROJECT COST BREAKDOWN", margin + 3, y + 5.4);
  y += 13;

  (projectDocument.lineItems || []).forEach((item, index) => {
    ensureRoom(15);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    writeWrapped(`${index + 1}. ${item.description}`, margin, 112, 4.5);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.text(`${Number(item.quantity || 0)} ${item.unit || "item"}`, margin + 115, y - 4.5);
    doc.text(formatDocumentMoney(item.amount), margin + 138, y - 4.5);
    doc.setDrawColor(229, 235, 233);
    doc.line(margin, y, margin + usableWidth, y);
    y += 4;
  });

  ensureRoom(39);
  y += 4;
  doc.setFontSize(9);
  doc.text("Subtotal", 122, y);
  doc.text(formatDocumentMoney(projectDocument.subtotal), 156, y);
  y += 6;
  if (Number(projectDocument.discount || 0) > 0) {
    doc.text("Discount", 122, y);
    doc.text(`- ${formatDocumentMoney(projectDocument.discount)}`, 156, y);
    y += 6;
  }
  if (Number(projectDocument.tax || 0) > 0) {
    doc.text("Tax", 122, y);
    doc.text(formatDocumentMoney(projectDocument.tax), 156, y);
    y += 6;
  }
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("Total", 122, y);
  doc.text(formatDocumentMoney(projectDocument.total), 156, y);
  y += 11;

  if (projectDocument.type === "quotation") {
    doc.setFontSize(9);
    doc.text(
      `Customer equity (${Number(projectDocument.equityPercentage || 20)}%): ${formatDocumentMoney(projectDocument.equityAmount)}`,
      margin,
      y
    );
    y += 6;
    doc.text(`Requested bank finance: ${formatDocumentMoney(projectDocument.bankFinanceAmount)}`, margin, y);
    y += 10;
  }

  doc.setFont("helvetica", "bold");
  doc.setFontSize(9);
  doc.text("Project scope and notes", margin, y);
  y += 6;
  doc.setFont("helvetica", "normal");
  writeWrapped(projectDocument.project?.scope || projectDocument.notes || "As described in the approved project assessment.", margin, usableWidth);

  if (projectDocument.terms) {
    y += 5;
    doc.setFont("helvetica", "bold");
    doc.text("Terms", margin, y);
    y += 6;
    doc.setFont("helvetica", "normal");
    writeWrapped(projectDocument.terms, margin, usableWidth);
  }

  ensureRoom(20);
  y += 8;
  doc.setDrawColor(15, 79, 72);
  doc.line(margin, y, margin + usableWidth, y);
  y += 7;
  doc.setFontSize(8);
  doc.setTextColor(77, 91, 87);
  writeWrapped(
    "BuiltRight Services Ltd | 1b Adeniji Street, Off Odusami Street, Ogba, Lagos | info@builtrightltd.com",
    margin,
    usableWidth,
    4
  );

  return Buffer.from(doc.output("arraybuffer"));
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

    try {
      await sendEmail({
        to: user.email,
        subject: "Welcome to BuiltRight Services",
        html: `<h2>Welcome to BuiltRight Services Ltd</h2><p>Hello ${safeHtml(user.fullName)},</p><p>Your account has been created successfully. You can now request solar financing, receive quotations, review invoices, and track your project from your customer profile.</p><p><a href="${frontendUrl()}/customer/dashboard">Open my BuiltRight profile</a></p>`,
      });
    } catch (mailError) {
      console.error("CUSTOMER WELCOME EMAIL ERROR:", mailError.message);
    }

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

    if (user.role !== "customer") {
      return res.status(403).json({
        status: false,
        message: "Use the installer portal to access an installer account.",
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
        location: customer.location || "",
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

const activeInstallerStatuses = ["assigned", "accepted", "scheduled"];

const chooseInstaller = async (excludedIds = []) => {
  const excluded = excludedIds.filter(Boolean).map((id) => String(id));
  const installers = await User.find({
    role: "installer",
    isActive: true,
    "installerProfile.availability": "available",
    "installerProfile.activatedAt": { $ne: null },
    ...(excluded.length ? { _id: { $nin: excluded } } : {}),
  });
  if (!installers.length) return null;
  const workloads = await Promise.all(installers.map(async (installer) => ({
    installer,
    assignments: await LoanRequest.countDocuments({
      "installerAssignment.installer": installer._id,
      "installerAssignment.status": { $in: activeInstallerStatuses },
      "testRun.isTest": { $ne: true },
    }),
  })));
  workloads.sort((left, right) => left.assignments - right.assignments || left.installer.createdAt - right.installer.createdAt);
  return workloads[0].installer;
};

const sendInstallerAssignmentEmail = async (loanRequest, installer, reassigned = false) => {
  const profileUrl = `${frontendUrl()}/installer/assignments`;
  await sendEmail({
    to: installer.email,
    subject: `${reassigned ? "Reassigned" : "New"} inspection assignment - ${loanRequest.reference}`,
    html: `<h2>${reassigned ? "Inspection reassigned" : "New inspection assignment"}</h2><p>Hello ${safeHtml(installer.fullName)},</p><p>You have been assigned to ${safeHtml(loanRequest.customer.fullName)}'s solar-financing project.</p><ul><li><strong>Reference:</strong> ${safeHtml(loanRequest.reference)}</li><li><strong>Customer phone:</strong> ${safeHtml(loanRequest.customer.phone)}</li><li><strong>Project location:</strong> ${safeHtml(loanRequest.customer.location || "To be confirmed")}</li></ul><p>Please sign in, accept or decline the assignment, and arrange a convenient inspection time with the customer.</p><p><a href="${profileUrl}">Open installer profile</a></p>`,
  });
};

const assignInstallerToLoanRequest = async (loanRequest, { excludedIds = [], reassigned = false, note = "" } = {}) => {
  const installer = await chooseInstaller(excludedIds);
  if (!installer) return null;
  const previousHistory = loanRequest.installerAssignment?.history || [];
  loanRequest.installerAssignment = {
    installer: installer._id,
    installerName: installer.fullName,
    installerEmail: installer.email,
    status: "assigned",
    assignedAt: new Date(),
    acceptedAt: null,
    declinedAt: null,
    declineReason: "",
    reassignmentCount: Number(loanRequest.installerAssignment?.reassignmentCount || 0) + (reassigned ? 1 : 0),
    history: [...previousHistory, { installer: installer._id, installerName: installer.fullName, status: "assigned", note: note || (reassigned ? "Automatically reassigned after decline." : "Automatically assigned when financing request was submitted."), changedAt: new Date() }],
  };
  loanRequest.status = "internal-review";
  loanRequest.statusHistory.push({
    status: "internal-review",
    source: "system",
    note: `Inspection assigned to ${installer.fullName}.`,
  });
  return installer;
};

const sendSubmissionConfirmationEmail = async (loanRequest) => {
  const installerName = loanRequest.installerAssignment?.installerName || "a BuiltRight installer";
  const isOutright = loanRequest.paymentMethod === "outright";
  await sendEmail({
    to: loanRequest.customer.email,
    subject: `BuiltRight ${isOutright ? "outright-purchase" : "financing"} request received - ${loanRequest.reference}`,
    html: `<h2>Your ${isOutright ? "outright-purchase" : "financing"} request was submitted successfully</h2><p>Hello ${safeHtml(loanRequest.customer.fullName)},</p><p>We have received your request ${safeHtml(loanRequest.reference)}. ${safeHtml(installerName)} will contact you shortly to arrange a convenient time for your site inspection.</p><p>After the inspection, load audit, and due diligence, BuiltRight will prepare your final project quotation for approval.${isOutright ? " Once approved, you will receive a BuiltRight invoice for the full confirmed project cost." : ""}</p>`,
  });
};

const autoCreateAndSendQuotation = async (loanRequest, createdBy) => {
  const existingQuotation = await ProjectDocument.findOne({
    financingRequest: loanRequest._id,
    type: "quotation",
    status: { $in: ["draft", "sent", "approved"] },
  });
  if (existingQuotation) return existingQuotation;

  const materialLines = (loanRequest.inspectionCosts || [])
    .filter((item) => String(item?.label || "").trim() && Number(item.amount) > 0)
    .map((item) => ({
      category: "installation-materials",
      description: String(item.label).trim(),
      quantity: 1,
      unit: "item",
      unitPrice: Number(item.amount),
      amount: Number(item.amount),
      source: "inspection",
    }));
  if (!materialLines.length) {
    const error = new Error("Add at least one confirmed installation material or work cost before marking the assessment as passed.");
    error.statusCode = 409;
    throw error;
  }

  const productLines = (loanRequest.items || []).map((item) => {
    const quantity = Math.max(1, Number(item.quantity || 1));
    const unitPrice = Math.max(0, Number(item.price || 0));
    return {
      category: "solar-system",
      description: String(item.name || "Selected solar system").trim(),
      quantity,
      unit: "system",
      unitPrice,
      amount: Math.round(quantity * unitPrice * 100) / 100,
      source: "confirmed",
    };
  }).filter((item) => item.amount > 0);
  if (!productLines.length && Number(loanRequest.estimatedAmount) > 0) {
    productLines.push({
      category: "solar-system",
      description: "Selected solar system",
      quantity: 1,
      unit: "system",
      unitPrice: Number(loanRequest.estimatedAmount),
      amount: Number(loanRequest.estimatedAmount),
      source: "confirmed",
    });
  }

  const confirmedLines = (loanRequest.upfrontCosts || [])
    .filter((item) => String(item?.label || "").trim() && Number(item.amount) > 0)
    .map((item) => ({
      category: "other",
      description: String(item.label).trim(),
      quantity: 1,
      unit: "fee",
      unitPrice: Number(item.amount),
      amount: Number(item.amount),
      source: "confirmed",
    }));
  const lineItems = [...productLines, ...confirmedLines, ...materialLines];
  const subtotal = lineItems.reduce((sum, item) => sum + item.amount, 0);
  if (subtotal <= 0) {
    const error = new Error("The selected solar system price is required before a final quotation can be generated.");
    error.statusCode = 409;
    throw error;
  }

  const isBankFinancing = loanRequest.paymentMethod !== "outright";
  const equityPercentage = isBankFinancing ? Number(loanRequest.deposit?.percentage || 20) : 100;
  const equityAmount = Math.round(subtotal * (equityPercentage / 100) * 100) / 100;
  const version = (await ProjectDocument.countDocuments({ financingRequest: loanRequest._id, type: "quotation" })) + 1;
  const firstItem = loanRequest.items?.[0];
  const quotation = await ProjectDocument.create({
    reference: `BRQ-${String(loanRequest.reference || loanRequest._id).replace(/^BRF-/, "")}-V${version}`,
    financingRequest: loanRequest._id,
    type: "quotation",
    version,
    status: "draft",
    title: `${firstItem?.capacity || "Solar"} project quotation`,
    customer: { ...loanRequest.customer },
    project: {
      systemName: firstItem?.name || "Solar power system",
      systemCapacity: firstItem?.capacity || "",
      propertyType: loanRequest.inspection?.propertyType || "",
      cableDistance: loanRequest.inspection?.cableDistance || "",
      mountingMethod: loanRequest.inspection?.mountingMethod || "",
      siteAddress: loanRequest.customer?.location || "",
      scope: "System supply, site-confirmed installation materials, installation and commissioning.",
    },
    lineItems,
    subtotal,
    total: subtotal,
    equityPercentage,
    equityAmount,
    bankFinanceAmount: isBankFinancing ? Math.round((subtotal - equityAmount) * 100) / 100 : 0,
    terms: isBankFinancing
      ? "Quotation is subject to customer approval and bank credit approval. Work begins only after the inspection fee, equity deposit, and bank disbursement are confirmed."
      : "Quotation is subject to customer approval and payment of the final BuiltRight invoice. Work begins only after the inspection fee and full project payment are confirmed.",
    createdBy,
  });

  const pdf = buildProjectDocumentPdf(quotation);
  const portalUrl = `${frontendUrl()}/customer/documents`;
  if (loanRequest.testRun?.suppressNotifications) {
    quotation.emailDelivery = { status: "not-sent", sentAt: null, error: "Suppressed for operations test run." };
    quotation.status = "sent";
    quotation.sentAt = new Date();
  } else {
    try {
      await sendEmail({
        to: quotation.customer.email,
        subject: `BuiltRight Project Quotation ${quotation.reference}`,
        html: `<h2>Your BuiltRight solar project quotation is ready</h2><p>Hello ${safeHtml(quotation.customer.fullName)},</p><p>Your site inspection, load audit, and due-diligence review have passed. Your full project quotation is attached and is now available in your customer profile for download and approval.</p><p><a href="${portalUrl}">Review and accept quotation</a></p>`,
        attachments: [{ filename: `BuiltRight-Quotation-${quotation.reference}.pdf`, content: pdf, contentType: "application/pdf" }],
      });
      quotation.emailDelivery = { status: "sent", sentAt: new Date(), error: "" };
      quotation.status = "sent";
      quotation.sentAt = new Date();
    } catch (error) {
      quotation.emailDelivery = { status: "failed", sentAt: null, error: error.message };
    }
  }

  const bankEmail = isBankFinancing && !loanRequest.testRun?.suppressNotifications ? (process.env.BANK_APPLICATION_EMAIL || "") : "";
  quotation.bankDelivery = { status: bankEmail ? "pending" : "not-ready", sentAt: null, error: "" };
  if (bankEmail) {
    try {
      await sendEmail({
        to: bankEmail,
        subject: `BuiltRight quotation for bank application - ${quotation.reference}`,
        html: `<h2>Solar financing quotation ready for bank application</h2><p><strong>Customer:</strong> ${safeHtml(quotation.customer.fullName)}</p><p><strong>BuiltRight request:</strong> ${safeHtml(loanRequest.reference)}</p><p><strong>Quotation:</strong> ${safeHtml(quotation.reference)}</p><p><strong>Total project cost:</strong> ${formatDocumentMoney(quotation.total)}</p><p>The quotation is attached for the customer's upcoming credit and KYC journey.</p>`,
        attachments: [{ filename: `BuiltRight-Quotation-${quotation.reference}.pdf`, content: pdf, contentType: "application/pdf" }],
      });
      quotation.bankDelivery = { status: "sent", sentAt: new Date(), error: "" };
    } catch (error) {
      quotation.bankDelivery = { status: "failed", sentAt: null, error: error.message };
    }
  }
  await quotation.save();

  loanRequest.finalProjectCost = quotation.total;
  loanRequest.deposit.percentage = equityPercentage;
  loanRequest.deposit.amount = equityAmount;
  loanRequest.quotation = { status: quotation.status === "sent" ? "sent" : "draft", document: quotation._id, reference: quotation.reference, version, sentAt: quotation.sentAt, approvedAt: null, changesRequestedAt: null };
  loanRequest.status = quotation.status === "sent" ? "quotation-sent" : "quotation-draft";
  loanRequest.statusHistory.push({ status: loanRequest.status, source: "system", note: `Final quotation ${quotation.reference} generated from the passed installer assessment.` });
  return quotation;
};

app.post("/api/loan-request", async (req, res) => {
  try {
    const {
      customer,
      items,
      estimatedAmount,
      productSource,
      paymentMethod,
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
    const selectedPaymentMethod = paymentMethod === "outright" ? "outright" : "bank-financing";
    const selectedFinanceInstitution = selectedPaymentMethod === "outright"
      ? "Not applicable — outright payment"
      : (financeInstitution || "Bank partner pending");
    const equityPercentage = selectedPaymentMethod === "outright" ? 100 : (selectedFinanceInstitution === "LOTUS Bank" ? 10 : 20);

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
        location: customer.location || "",
      },
      productSource: selectedProductSource,
      paymentMethod: selectedPaymentMethod,
      installationProvider: "BuiltRight Services Ltd",
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
      bankApplication: { provider: selectedFinanceInstitution, status: selectedPaymentMethod === "outright" ? "not-required" : "not-started" },
      deposit: { percentage: equityPercentage, status: "not-due" },
      assessment: {
        status: "open",
        triggeredAt: new Date(),
        dueDiligence: {
          status: "pending",
          result: "pending",
          checklist: [
            { key: "identity-contact", label: "Customer identity and contact verified", status: "pending" },
            { key: "property-authority", label: "Property ownership or installation authority verified", status: "pending" },
            { key: "site-access", label: "Site access and installation permissions confirmed", status: "pending" },
            { key: "technical-suitability", label: "Roof, electrical, and structural suitability confirmed", status: "pending" },
            { key: "financing-consent", label: "Financing data-sharing consent recorded", status: "pending" },
          ],
        },
      },
      status: "submitted",
      statusHistory: [
        {
          status: "submitted",
          source: "customer",
          note: selectedPaymentMethod === "outright" ? "Customer submitted an outright-purchase project request." : "Customer submitted a financing request.",
        },
      ],
      notes: notes || "",
    });

    const assignedInstaller = await assignInstallerToLoanRequest(loanRequest);
    await loanRequest.save();

    try {
      await sendSubmissionConfirmationEmail(loanRequest);
    } catch (mailError) {
      console.error("CUSTOMER FINANCING SUBMISSION EMAIL ERROR:", mailError.message);
    }

    if (assignedInstaller) {
      try {
        await sendInstallerAssignmentEmail(loanRequest, assignedInstaller);
      } catch (mailError) {
        console.error("INSTALLER ASSIGNMENT EMAIL ERROR:", mailError.message);
      }
    }

    try {
      await sendEmail({
        to: process.env.ADMIN_ALERT_EMAIL || process.env.SMTP_USER,
        subject: `New ${selectedPaymentMethod === "outright" ? "Outright Purchase" : "Financing"} Request - ${customer.fullName}`,
        html: `
          <h2>New Financing Request</h2>
          <p><strong>Name:</strong> ${customer.fullName}</p>
          <p><strong>Email:</strong> ${customer.email}</p>
          <p><strong>Phone:</strong> ${customer.phone}</p>
          <p><strong>Product Source:</strong> ${selectedProductSource}</p>
          <p><strong>Payment Route:</strong> ${selectedPaymentMethod === "outright" ? "Outright payment after final quotation" : "Bank financing"}</p>
          <p><strong>Installation Provider:</strong> BuiltRight Services Ltd</p>
          <p><strong>Finance Institution:</strong> ${selectedFinanceInstitution}</p>
          <p><strong>Assigned installer:</strong> ${safeHtml(loanRequest.installerAssignment?.installerName || "No active installer available")}</p>
          <p><strong>Status:</strong> ${safeHtml(loanRequest.status)}</p>
        `,
      });
    } catch (mailError) {
      console.error("ADMIN FINANCING EMAIL ERROR:", mailError.message);
    }

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
    const loanRequests = await LoanRequest.find({ "testRun.isTest": { $ne: true } }).sort({ createdAt: -1 });

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

app.delete("/api/admin/orders/:id", requireAdminAuth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).lean();
    if (!order) return res.status(404).json({ status: false, message: "Order not found." });

    await Promise.all([
      ProjectDocument.deleteMany({ order: order._id }),
      Order.deleteOne({ _id: order._id }),
    ]);

    return res.json({
      status: true,
      message: `Order ${order.orderNumber || order.reference} and its linked invoice records were permanently deleted.`,
    });
  } catch (error) {
    console.error("DELETE ORDER ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Failed to permanently delete order." });
  }
});

app.get("/api/loan-requests/:id/workspace", requireAdminAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findById(req.params.id).lean();
    if (!loanRequest) {
      return res.status(404).json({ status: false, message: "Financing case not found." });
    }

    const documents = await ProjectDocument.find({ financingRequest: loanRequest._id })
      .sort({ createdAt: -1 })
      .lean();
    return res.json({ status: true, loanRequest, documents });
  } catch (error) {
    console.error("LOAD FINANCING WORKSPACE ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load the financing workspace." });
  }
});

/* =========================
   INSTALLER AUTH
========================= */

app.post("/api/installer/activate", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password || password.length < 8) {
      return res.status(400).json({ status: false, message: "A valid invitation token and an 8-character password are required." });
    }
    const installer = await User.findOne({
      role: "installer",
      "installerProfile.invitationToken": token,
      "installerProfile.invitationExpiresAt": { $gt: new Date() },
    });
    if (!installer) {
      return res.status(400).json({ status: false, message: "This installer invitation is invalid or has expired." });
    }
    installer.password = await bcrypt.hash(password, 10);
    installer.isActive = true;
    installer.installerProfile.invitationToken = "";
    installer.installerProfile.invitationExpiresAt = null;
    installer.installerProfile.activatedAt = new Date();
    await installer.save();
    return res.json({ status: true, message: "Installer account activated. You can now sign in." });
  } catch (error) {
    console.error("INSTALLER ACTIVATION ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Installer account could not be activated." });
  }
});

app.post("/api/installer/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const installer = await User.findOne({ email: String(email || "").toLowerCase(), role: "installer" });
    if (!installer || !installer.isActive || !(await bcrypt.compare(password || "", installer.password))) {
      return res.status(401).json({ status: false, message: "Invalid installer credentials." });
    }
    const token = createToken({ id: installer._id, email: installer.email, role: "installer" });
    return res.json({
      status: true,
      token,
      user: { id: installer._id, fullName: installer.fullName, email: installer.email, role: installer.role },
    });
  } catch (error) {
    console.error("INSTALLER LOGIN ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Installer login failed." });
  }
});

app.get("/api/installer/assignments", requireInstallerAuth, async (req, res) => {
  try {
    const assignments = await LoanRequest.find({
      "installerAssignment.installer": req.installer.id,
      "testRun.isTest": { $ne: true },
    })
      .sort({ "installerAssignment.assignedAt": -1 })
      .lean();
    return res.json({ status: true, assignments });
  } catch (error) {
    console.error("INSTALLER ASSIGNMENTS ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load installer assignments." });
  }
});

app.patch("/api/installer/assignments/:id/accept", requireInstallerAuth, async (req, res) => {
  try {
    const { scheduledAt, location, inspectionFeeAmount } = req.body;
    const loanRequest = await LoanRequest.findOne({ _id: req.params.id, "installerAssignment.installer": req.installer.id });
    if (!loanRequest || !["assigned", "accepted"].includes(loanRequest.installerAssignment?.status)) {
      return res.status(404).json({ status: false, message: "This assignment is no longer available for acceptance." });
    }
    if (!scheduledAt && !location && !inspectionFeeAmount) {
      loanRequest.installerAssignment.status = "accepted";
      loanRequest.installerAssignment.acceptedAt ||= new Date();
      loanRequest.installerAssignment.history.push({ installer: req.installer.id, installerName: loanRequest.installerAssignment.installerName, status: "accepted", note: "Installer accepted the assignment and will contact the customer before scheduling.", changedAt: new Date() });
      await loanRequest.save();
      return res.json({ status: true, message: "Assignment accepted. Contact the customer, then enter the agreed inspection schedule and fee.", loanRequest });
    }
    if (!scheduledAt || !location || Number(inspectionFeeAmount) <= 0) {
      return res.status(400).json({ status: false, message: "Inspection date, time, location, and a fee amount are required." });
    }
    const scheduledDate = new Date(scheduledAt);
    if (Number.isNaN(scheduledDate.getTime()) || scheduledDate <= new Date()) {
      return res.status(400).json({ status: false, message: "Choose a future inspection date and time." });
    }
    loanRequest.installerAssignment.status = "scheduled";
    loanRequest.installerAssignment.acceptedAt = new Date();
    loanRequest.installerAssignment.history.push({ installer: req.installer.id, installerName: loanRequest.installerAssignment.installerName, status: "accepted", note: "Installer accepted and scheduled the inspection.", changedAt: new Date() });
    loanRequest.inspection.status = "scheduled";
    loanRequest.inspection.scheduledAt = scheduledDate;
    loanRequest.inspection.assignee = loanRequest.installerAssignment.installerName;
    loanRequest.inspection.notes = `Inspection location: ${location}`;
    loanRequest.inspection.feeAmount = Number(inspectionFeeAmount);
    loanRequest.inspection.feeStatus = "payment-requested";
    loanRequest.assessment.inspection.status = "scheduled";
    loanRequest.assessment.status = "in-progress";
    loanRequest.status = "inspection-scheduled";
    loanRequest.statusHistory.push({ status: "inspection-scheduled", source: "installer", note: `Inspection scheduled by ${loanRequest.installerAssignment.installerName}.` });
    await loanRequest.save();
    try {
      await sendEmail({
        to: loanRequest.customer.email,
        subject: `BuiltRight inspection scheduled - ${loanRequest.reference}`,
        html: `<h2>Your site inspection is scheduled</h2><p>Hello ${safeHtml(loanRequest.customer.fullName)},</p><p>${safeHtml(loanRequest.installerAssignment.installerName)} has scheduled your site inspection.</p><ul><li><strong>Date and time:</strong> ${safeHtml(scheduledDate.toLocaleString("en-NG", { dateStyle: "full", timeStyle: "short" }))}</li><li><strong>Location:</strong> ${safeHtml(location)}</li><li><strong>Inspection fee:</strong> ${formatNaira(inspectionFeeAmount)}</li></ul><p>Please make the inspection-fee payment using the details below. Then sign in to your BuiltRight customer profile, upload your payment proof, and click <strong>I have paid — submit proof</strong>. Your installer can begin the inspection only after confirming receipt.</p><ul><li><strong>Bank:</strong> ${safeHtml(inspectionPaymentDetails.bank)}</li><li><strong>Account number:</strong> ${safeHtml(inspectionPaymentDetails.accountNumber)}</li><li><strong>Account name:</strong> ${safeHtml(inspectionPaymentDetails.accountName)}</li></ul><p><a href="${frontendUrl()}/customer/financing">Open customer profile</a></p>`,
      });
    } catch (mailError) {
      console.error("INSPECTION SCHEDULE EMAIL ERROR:", mailError.message);
    }
    return res.json({ status: true, message: "Inspection accepted, scheduled, and emailed to the customer.", loanRequest });
  } catch (error) {
    console.error("ACCEPT INSTALLER ASSIGNMENT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not accept the inspection assignment." });
  }
});

app.patch("/api/installer/assignments/:id/payment-received", requireInstallerAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findOne({ _id: req.params.id, "installerAssignment.installer": req.installer.id });
    if (!loanRequest || !["scheduled", "accepted"].includes(loanRequest.installerAssignment?.status)) {
      return res.status(404).json({ status: false, message: "This inspection assignment is not available for payment confirmation." });
    }
    if (loanRequest.inspection?.feeStatus !== "proof-submitted" || !loanRequest.inspection?.paymentProof?.url) {
      return res.status(409).json({ status: false, message: "The customer must upload proof of the inspection-fee payment before it can be confirmed." });
    }
    loanRequest.inspection.feeStatus = "payment-confirmed";
    loanRequest.inspection.paymentConfirmedAt = new Date();
    loanRequest.inspection.status = "in-progress";
    loanRequest.installerAssignment.status = "accepted";
    loanRequest.assessment.status = "in-progress";
    loanRequest.statusHistory.push({ status: "inspection-scheduled", source: "installer", note: `Inspection fee confirmed by ${loanRequest.installerAssignment.installerName}; inspection is now in progress.` });
    await loanRequest.save();
    return res.json({ status: true, message: "Inspection payment confirmed. You can now proceed with the site visit and submit the field report.", loanRequest });
  } catch (error) {
    console.error("CONFIRM INSPECTION PAYMENT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not confirm the inspection payment." });
  }
});

app.patch("/api/installer/assignments/:id/decline", requireInstallerAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findOne({ _id: req.params.id, "installerAssignment.installer": req.installer.id });
    if (!loanRequest || loanRequest.installerAssignment?.status !== "assigned") {
      return res.status(404).json({ status: false, message: "This assignment is no longer available for decline." });
    }
    const previousInstaller = loanRequest.installerAssignment;
    loanRequest.installerAssignment.history.push({ installer: previousInstaller.installer, installerName: previousInstaller.installerName, status: "declined", note: String(req.body.reason || "Installer declined the assignment."), changedAt: new Date() });
    const replacement = await assignInstallerToLoanRequest(loanRequest, {
      excludedIds: [previousInstaller.installer],
      reassigned: true,
      note: `Automatically reassigned after ${previousInstaller.installerName} declined.`,
    });
    if (!replacement) {
      loanRequest.installerAssignment.status = "declined";
      loanRequest.installerAssignment.declinedAt = new Date();
      loanRequest.installerAssignment.declineReason = String(req.body.reason || "Installer declined the assignment.");
      loanRequest.statusHistory.push({ status: loanRequest.status, source: "system", note: "No alternate active installer is available; admin reassignment is required." });
    }
    await loanRequest.save();
    if (replacement) {
      try { await sendInstallerAssignmentEmail(loanRequest, replacement, true); } catch (mailError) { console.error("REASSIGNMENT EMAIL ERROR:", mailError.message); }
      try {
        await sendEmail({
          to: loanRequest.customer.email,
          subject: `BuiltRight installer update - ${loanRequest.reference}`,
          html: `<p>Hello ${safeHtml(loanRequest.customer.fullName)},</p><p>Your inspection has been reassigned to ${safeHtml(replacement.fullName)}. They will contact you shortly to arrange a convenient visit time.</p>`,
        });
      } catch (mailError) { console.error("CUSTOMER REASSIGNMENT EMAIL ERROR:", mailError.message); }
    }
    return res.json({ status: true, message: replacement ? `Assignment reassigned to ${replacement.fullName}.` : "No alternate installer is currently active. An administrator must reassign this request.", loanRequest });
  } catch (error) {
    console.error("DECLINE INSTALLER ASSIGNMENT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not decline the inspection assignment." });
  }
});

app.patch("/api/installer/assignments/:id/report", requireInstallerAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findOne({ _id: req.params.id, "installerAssignment.installer": req.installer.id });
    if (!loanRequest || !["accepted", "scheduled"].includes(loanRequest.installerAssignment?.status)) {
      return res.status(404).json({ status: false, message: "Only an accepted inspection assignment can be updated." });
    }
    const { inspection = {}, loadAudit = {}, dueDiligence = {}, inspectionCosts = [] } = req.body;
    const copyFields = (target, source, fields) => fields.forEach((field) => {
      if (Object.prototype.hasOwnProperty.call(source, field)) target[field] = source[field];
    });
    copyFields(loanRequest.assessment.inspection, inspection, ["status", "result", "notes"]);
    copyFields(loanRequest.assessment.loadAudit, loadAudit, ["status", "result", "peakLoadKw", "dailyEnergyKwh", "criticalLoadKw", "recommendedInverterKva", "recommendedBatteryKwh", "recommendedSolarKw", "backupHours", "appliances", "notes"]);
    copyFields(loanRequest.assessment.dueDiligence, dueDiligence, ["status", "result", "checklist", "notes"]);
    loanRequest.assessment.inspection.completedBy = loanRequest.installerAssignment.installerName;
    loanRequest.assessment.loadAudit.completedBy = loanRequest.installerAssignment.installerName;
    loanRequest.assessment.dueDiligence.completedBy = loanRequest.installerAssignment.installerName;
    if (Array.isArray(inspectionCosts)) {
      loanRequest.inspectionCosts = inspectionCosts
        .filter((item) => item?.label)
        .map((item) => ({ label: String(item.label), amount: Number(item.amount || 0) }));
    }
    if (loanRequest.assessment.inspection.status === "completed") {
      loanRequest.assessment.inspection.completedAt ||= new Date();
      loanRequest.inspection.status = "completed";
      loanRequest.inspection.completedAt ||= new Date();
      loanRequest.installerAssignment.status = "completed";
    }
    if (loanRequest.assessment.loadAudit.status === "completed") loanRequest.assessment.loadAudit.completedAt ||= new Date();
    if (loanRequest.assessment.dueDiligence.status === "completed") loanRequest.assessment.dueDiligence.completedAt ||= new Date();
    const inspectionPassed = loanRequest.assessment.inspection.status === "completed" && loanRequest.assessment.inspection.result === "pass";
    const auditPassed = loanRequest.assessment.loadAudit.status === "completed" && loanRequest.assessment.loadAudit.result === "pass" && [loanRequest.assessment.loadAudit.peakLoadKw, loanRequest.assessment.loadAudit.dailyEnergyKwh, loanRequest.assessment.loadAudit.recommendedInverterKva, loanRequest.assessment.loadAudit.recommendedBatteryKwh, loanRequest.assessment.loadAudit.recommendedSolarKw].every((value) => Number(value) > 0);
    const dueDiligencePassed = loanRequest.assessment.dueDiligence.status === "completed" && loanRequest.assessment.dueDiligence.result === "pass" && (loanRequest.assessment.dueDiligence.checklist || []).length > 0 && (loanRequest.assessment.dueDiligence.checklist || []).every((item) => ["pass", "not-applicable"].includes(item.status));
    if ([loanRequest.assessment.inspection.result, loanRequest.assessment.loadAudit.result, loanRequest.assessment.dueDiligence.result].includes("fail")) {
      loanRequest.assessment.status = "failed";
      loanRequest.status = "due-diligence-failed";
    } else if (inspectionPassed && auditPassed && dueDiligencePassed) {
      loanRequest.assessment.status = "passed";
      loanRequest.status = "due-diligence-passed";
    } else {
      loanRequest.assessment.status = "in-progress";
      loanRequest.status = auditPassed ? "load-audit-completed" : inspectionPassed ? "inspection-completed" : "inspection-scheduled";
    }
    loanRequest.statusHistory.push({ status: loanRequest.status, source: "installer", note: `Inspection, load-audit, due-diligence, and material report updated by ${loanRequest.installerAssignment.installerName}.` });
    let quotation = null;
    if (loanRequest.assessment.status === "passed") {
      quotation = await autoCreateAndSendQuotation(loanRequest, loanRequest.installerAssignment.installerName);
    }
    await loanRequest.save();
    return res.json({ status: true, message: quotation?.status === "sent" ? "Assessment passed. The final quotation was emailed to the customer and is available in their profile." : loanRequest.assessment.status === "passed" ? "Assessment passed. The quotation was generated but needs an operations email retry." : "Installer report saved.", loanRequest, quotation });
  } catch (error) {
    console.error("INSTALLER REPORT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not save the installer report." });
  }
});

app.patch("/api/loan-requests/:id/assessment", requireAdminAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findById(req.params.id);
    if (!loanRequest) {
      return res.status(404).json({ status: false, message: "Financing case not found." });
    }

    const { inspection, loadAudit, dueDiligence } = req.body;
    loanRequest.assessment ||= {};
    loanRequest.assessment.inspection ||= {};
    loanRequest.assessment.loadAudit ||= {};
    loanRequest.assessment.dueDiligence ||= { checklist: [] };
    const allowedInspectionFields = ["status", "result", "completedBy", "notes"];
    const allowedLoadAuditFields = [
      "status",
      "result",
      "peakLoadKw",
      "dailyEnergyKwh",
      "criticalLoadKw",
      "recommendedInverterKva",
      "recommendedBatteryKwh",
      "recommendedSolarKw",
      "backupHours",
      "appliances",
      "completedBy",
      "notes",
    ];
    const allowedDueDiligenceFields = ["status", "result", "checklist", "completedBy", "notes"];

    const assignAllowed = (target, source, fields) => {
      if (!source) return;
      fields.forEach((field) => {
        if (Object.prototype.hasOwnProperty.call(source, field)) {
          target[field] = source[field];
        }
      });
    };

    assignAllowed(loanRequest.assessment.inspection, inspection, allowedInspectionFields);
    assignAllowed(loanRequest.assessment.loadAudit, loadAudit, allowedLoadAuditFields);
    assignAllowed(loanRequest.assessment.dueDiligence, dueDiligence, allowedDueDiligenceFields);

    if (loanRequest.assessment.inspection.status === "completed") {
      loanRequest.assessment.inspection.completedAt ||= new Date();
      loanRequest.inspection.status = "completed";
      loanRequest.inspection.completedAt ||= new Date();
    }
    if (loanRequest.assessment.loadAudit.status === "completed") {
      loanRequest.assessment.loadAudit.completedAt ||= new Date();
    }
    if (loanRequest.assessment.dueDiligence.status === "completed") {
      loanRequest.assessment.dueDiligence.completedAt ||= new Date();
    }

    const inspectionPassed =
      loanRequest.assessment.inspection.status === "completed" &&
      loanRequest.assessment.inspection.result === "pass";
    const loadAuditHasSizing = [
      loanRequest.assessment.loadAudit.peakLoadKw,
      loanRequest.assessment.loadAudit.dailyEnergyKwh,
      loanRequest.assessment.loadAudit.recommendedInverterKva,
      loanRequest.assessment.loadAudit.recommendedBatteryKwh,
      loanRequest.assessment.loadAudit.recommendedSolarKw,
    ].every((value) => Number(value) > 0);
    const loadAuditPassed =
      loanRequest.assessment.loadAudit.status === "completed" &&
      loanRequest.assessment.loadAudit.result === "pass" &&
      loadAuditHasSizing;
    const dueDiligenceChecklist = loanRequest.assessment.dueDiligence.checklist || [];
    const dueDiligencePassed =
      loanRequest.assessment.dueDiligence.status === "completed" &&
      loanRequest.assessment.dueDiligence.result === "pass" &&
      dueDiligenceChecklist.length > 0 &&
      dueDiligenceChecklist.every(
        (item) => ["pass", "not-applicable"].includes(item.status)
      );
    const assessmentFailed = [
      loanRequest.assessment.inspection.result,
      loanRequest.assessment.loadAudit.result,
      loanRequest.assessment.dueDiligence.result,
    ].includes("fail");

    if (assessmentFailed) {
      loanRequest.assessment.status = "failed";
      loanRequest.status = "due-diligence-failed";
    } else if (inspectionPassed && loadAuditPassed && dueDiligencePassed) {
      loanRequest.assessment.status = "passed";
      loanRequest.status = "due-diligence-passed";
    } else {
      loanRequest.assessment.status = "in-progress";
      loanRequest.status = loadAuditPassed
        ? "load-audit-completed"
        : inspectionPassed
          ? "inspection-completed"
          : loanRequest.assessment.inspection.status === "scheduled"
            ? "inspection-scheduled"
            : "internal-review";
    }

    loanRequest.statusHistory.push({
      status: loanRequest.status,
      source: "admin",
      note: `Pre-credit assessment updated by ${req.admin?.email || "BuiltRight admin"}.`,
    });
    await loanRequest.save();

    return res.json({
      status: true,
      message:
        loanRequest.assessment.status === "passed"
          ? "Inspection, load audit, and due diligence passed. Quotation preparation is now unlocked."
          : "Assessment record updated.",
      loanRequest,
    });
  } catch (error) {
    console.error("UPDATE ASSESSMENT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not update the assessment." });
  }
});

app.post("/api/loan-requests/:id/quotation", requireAdminAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findById(req.params.id);
    if (!loanRequest) {
      return res.status(404).json({ status: false, message: "Financing case not found." });
    }

    if (loanRequest.assessment?.status !== "passed") {
      return res.status(409).json({
        status: false,
        code: "ASSESSMENT_NOT_PASSED",
        message: "Quotation is locked until inspection, load audit, and due diligence all pass.",
      });
    }

    const sourceItems = Array.isArray(req.body.lineItems) ? req.body.lineItems : [];
    if (sourceItems.length === 0) {
      return res.status(400).json({ status: false, message: "Add at least one quotation line item." });
    }

    const lineItems = sourceItems.map((item) => {
      const quantity = Math.max(0, Number(item.quantity || 0));
      const unitPrice = Math.max(0, Number(item.unitPrice || 0));
      return {
        category: item.category || "other",
        description: String(item.description || "").trim(),
        quantity,
        unit: String(item.unit || "item").trim(),
        unitPrice,
        amount: Math.round(quantity * unitPrice * 100) / 100,
        source: item.source || "manual",
      };
    });

    if (lineItems.some((item) => !item.description)) {
      return res.status(400).json({ status: false, message: "Every quotation item needs a description." });
    }

    const subtotal = lineItems.reduce((sum, item) => sum + item.amount, 0);
    const discount = Math.max(0, Number(req.body.discount || 0));
    const tax = Math.max(0, Number(req.body.tax || 0));
    const total = Math.max(0, subtotal - discount + tax);
    if (total <= 0) {
      return res.status(400).json({ status: false, message: "The final project quotation must have a positive total." });
    }
    const isBankFinancing = loanRequest.paymentMethod !== "outright";
    const equityPercentage = isBankFinancing
      ? (loanRequest.financeInstitution === "LOTUS Bank" ? 10 : 20)
      : 100;
    const equityAmount = Math.round(total * (equityPercentage / 100) * 100) / 100;
    const bankFinanceAmount = isBankFinancing ? Math.round((total - equityAmount) * 100) / 100 : 0;
    const version = (await ProjectDocument.countDocuments({
      financingRequest: loanRequest._id,
      type: "quotation",
    })) + 1;
    const firstItem = loanRequest.items?.[0];
    const reference = `BRQ-${String(loanRequest.reference || loanRequest._id).replace(/^BRF-/, "")}-V${version}`;

    const quotation = await ProjectDocument.create({
      reference,
      financingRequest: loanRequest._id,
      type: "quotation",
      version,
      status: "draft",
      title: req.body.title || `${firstItem?.capacity || "Solar"} project quotation`,
      customer: {
        fullName: loanRequest.customer.fullName,
        email: loanRequest.customer.email,
        phone: loanRequest.customer.phone,
        location: loanRequest.customer.location || "",
      },
      project: {
        systemName: req.body.project?.systemName || firstItem?.name || "Solar power system",
        systemCapacity: req.body.project?.systemCapacity || firstItem?.capacity || "",
        propertyType: req.body.project?.propertyType || loanRequest.inspection?.propertyType || "",
        cableDistance: req.body.project?.cableDistance || loanRequest.inspection?.cableDistance || "",
        mountingMethod: req.body.project?.mountingMethod || loanRequest.inspection?.mountingMethod || "",
        siteAddress: req.body.project?.siteAddress || loanRequest.customer.location || "",
        scope: req.body.project?.scope || "",
      },
      lineItems,
      subtotal,
      discount,
      tax,
      total,
      equityPercentage,
      equityAmount,
      bankFinanceAmount,
      terms: req.body.terms || (isBankFinancing
        ? "Quotation is subject to customer approval and bank credit approval. Work begins only after the equity deposit and bank disbursement are confirmed."
        : "Quotation is subject to customer approval and payment of the final BuiltRight invoice. Work begins only after full project payment is confirmed."),
      notes: req.body.notes || "",
      validUntil: req.body.validUntil || null,
      createdBy: req.admin?.email || "BuiltRight operations",
    });

    loanRequest.finalProjectCost = total;
    loanRequest.deposit.percentage = equityPercentage;
    loanRequest.deposit.amount = equityAmount;
    loanRequest.quotation = {
      status: "draft",
      document: quotation._id,
      reference: quotation.reference,
      version,
      sentAt: null,
      approvedAt: null,
      changesRequestedAt: null,
    };
    loanRequest.status = "quotation-draft";
    loanRequest.statusHistory.push({
      status: "quotation-draft",
      source: "admin",
      note: `Quotation ${quotation.reference} prepared from the passed assessment.`,
    });
    await loanRequest.save();

    return res.status(201).json({
      status: true,
      message: "Quotation draft generated.",
      quotation,
      loanRequest,
    });
  } catch (error) {
    console.error("CREATE QUOTATION ERROR:", error.message);
    return res.status(500).json({ status: false, message: error.message || "Could not generate quotation." });
  }
});

app.post("/api/loan-requests/:id/quotation/:documentId/send", requireAdminAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findById(req.params.id);
    const quotation = await ProjectDocument.findOne({
      _id: req.params.documentId,
      financingRequest: req.params.id,
      type: "quotation",
    });
    if (!loanRequest || !quotation) {
      return res.status(404).json({ status: false, message: "Quotation not found." });
    }
    if (loanRequest.assessment?.status !== "passed") {
      return res.status(409).json({ status: false, message: "The assessment must pass before a quotation can be sent." });
    }
    if (quotation.status !== "draft") {
      return res.status(409).json({ status: false, message: "Only a draft quotation can be sent to the customer." });
    }

    const pdf = buildProjectDocumentPdf(quotation);
    const portalUrl = `${process.env.FRONTEND_URL || "https://builtright-frontend.vercel.app"}/customer/documents`;

    try {
      await sendEmail({
        to: quotation.customer.email,
        subject: `BuiltRight Project Quotation ${quotation.reference}`,
        html: `
          <div style="font-family:Arial,sans-serif;line-height:1.7;color:#1c2b27;max-width:680px;margin:auto;">
            <h2>Your BuiltRight solar project quotation is ready</h2>
            <p>Hello ${escapeHtml(quotation.customer.fullName)},</p>
            <p>BuiltRight has completed the site inspection, load audit, and due-diligence review for your financing request.</p>
            <div style="background:#edf6f3;padding:18px;border-radius:12px;margin:18px 0;">
              <p><strong>Quotation:</strong> ${escapeHtml(quotation.reference)}</p>
              <p><strong>Total project cost:</strong> ${formatDocumentMoney(quotation.total)}</p>
              <p><strong>Your ${quotation.equityPercentage}% equity:</strong> ${formatDocumentMoney(quotation.equityAmount)}</p>
              <p><strong>Requested bank finance:</strong> ${formatDocumentMoney(quotation.bankFinanceAmount)}</p>
            </div>
            <p>The full quotation is attached. Sign in to your BuiltRight customer portal to view, download, approve, or request changes.</p>
            <p><a href="${portalUrl}" style="display:inline-block;background:#c92b32;color:white;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:bold;">Review quotation</a></p>
          </div>
        `,
        attachments: [
          {
            filename: `BuiltRight-Quotation-${quotation.reference}.pdf`,
            content: pdf,
            contentType: "application/pdf",
          },
        ],
      });
      quotation.emailDelivery = { status: "sent", sentAt: new Date(), error: "" };
    } catch (mailError) {
      quotation.emailDelivery = { status: "failed", sentAt: null, error: mailError.message };
      await quotation.save();
      return res.status(502).json({
        status: false,
        message: "Quotation was generated, but the customer email could not be delivered.",
      });
    }

    quotation.status = "sent";
    quotation.sentAt = new Date();
    await quotation.save();

    loanRequest.quotation ||= {};
    loanRequest.quotation.status = "sent";
    loanRequest.quotation.document = quotation._id;
    loanRequest.quotation.reference = quotation.reference;
    loanRequest.quotation.sentAt = quotation.sentAt;
    loanRequest.status = "quotation-sent";
    loanRequest.statusHistory.push({
      status: "quotation-sent",
      source: "admin",
      note: `Quotation ${quotation.reference} emailed to the customer for approval.`,
    });
    await loanRequest.save();

    return res.json({ status: true, message: "Quotation emailed to the customer.", quotation, loanRequest });
  } catch (error) {
    console.error("SEND QUOTATION ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not send the quotation." });
  }
});

app.post("/api/loan-requests/:id/documents/:documentId/send", requireAdminAuth, async (req, res) => {
  try {
    const projectDocument = await ProjectDocument.findOne({
      _id: req.params.documentId,
      financingRequest: req.params.id,
    });
    if (!projectDocument) {
      return res.status(404).json({ status: false, message: "Project document not found." });
    }
    if (projectDocument.type !== "invoice" || projectDocument.status !== "issued") {
      return res.status(409).json({
        status: false,
        message: "Use the quotation approval workflow for quotations. Only issued invoices can be sent here.",
      });
    }

    try {
      const pdf = buildProjectDocumentPdf(projectDocument);
      const portalUrl = `${process.env.FRONTEND_URL || "https://builtright-frontend.vercel.app"}/customer/documents`;
      await sendEmail({
        to: projectDocument.customer.email,
        subject: `BuiltRight Project Invoice ${projectDocument.reference}`,
        html: `
          <div style="font-family:Arial,sans-serif;line-height:1.7;color:#1c2b27;max-width:680px;margin:auto;">
            <h2>Your BuiltRight project invoice is ready</h2>
            <p>Hello ${escapeHtml(projectDocument.customer.fullName)},</p>
            <p>Your equity payment and the bank's disbursement have been confirmed. Your project invoice is attached.</p>
            <p>BuiltRight's delivery and installation team will contact you with the schedule and site instructions.</p>
            <p><a href="${portalUrl}" style="display:inline-block;background:#168f82;color:white;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:bold;">View project documents</a></p>
          </div>
        `,
        attachments: [{
          filename: `BuiltRight-Invoice-${projectDocument.reference}.pdf`,
          content: pdf,
          contentType: "application/pdf",
        }],
      });
      projectDocument.emailDelivery = { status: "sent", sentAt: new Date(), error: "" };
      projectDocument.sentAt ||= new Date();
      await projectDocument.save();
      return res.json({ status: true, message: "Invoice emailed to the customer.", document: projectDocument });
    } catch (mailError) {
      projectDocument.emailDelivery = { status: "failed", sentAt: null, error: mailError.message };
      await projectDocument.save();
      return res.status(502).json({ status: false, message: "The invoice email could not be delivered." });
    }
  } catch (error) {
    console.error("SEND PROJECT DOCUMENT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not send the project document." });
  }
});

app.patch("/api/loan-requests/:id/status", requireAdminAuth, async (req, res) => {
  try {
    const { status } = req.body;

    const allowedStatuses = [
      "submitted",
      "internal-review",
      "inspection-scheduled",
      "inspection-completed",
      "load-audit-completed",
      "due-diligence-passed",
      "due-diligence-failed",
      "quotation-draft",
      "quotation-sent",
      "quotation-approved",
      "quotation-prepared",
      "kyc-submitted",
      "credit-review",
      "rejected",
      "awaiting-deposit",
      "deposit-paid",
      "awaiting-disbursement",
      "disbursed",
      "order-created",
      "installation-in-progress",
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

    const workflowManagedStatuses = [
      "inspection-completed",
      "load-audit-completed",
      "due-diligence-passed",
      "due-diligence-failed",
      "quotation-draft",
      "quotation-sent",
      "quotation-approved",
      "quotation-prepared",
    ];
    if (workflowManagedStatuses.includes(status)) {
      return res.status(409).json({
        status: false,
        code: "DEDICATED_WORKFLOW_REQUIRED",
        message: "This stage is controlled by the assessment, quotation, or customer-approval workflow.",
      });
    }

    const bankControlledStatuses = [
      "sent-to-bank",
      "kyc-submitted",
      "credit-review",
      "approved",
      "awaiting-deposit",
      "deposit-paid",
      "awaiting-disbursement",
      "disbursed",
    ];
    if (
      bankControlledStatuses.includes(status) &&
      loanRequest.quotation?.status !== "approved"
    ) {
      return res.status(409).json({
        status: false,
        code: "CUSTOMER_QUOTATION_APPROVAL_REQUIRED",
        message: "The customer must approve the final quotation before the bank application can begin.",
      });
    }
    if (status === "sent-to-bank" && !loanRequest.bankApplication?.redirectUrl) {
      return res.status(409).json({
        status: false,
        code: "BANK_APPLICATION_LINK_REQUIRED",
        message: "The bank's hosted credit application link has not been configured.",
      });
    }

    let createdOrder = null;
    let createdInvoice = null;

    if (status === "disbursed") {
      const financingReference = `FIN-${loanRequest.reference || loanRequest._id}`;

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
          amount: loanRequest.finalProjectCost ?? loanRequest.estimatedAmount ?? null,
          date: new Date().toLocaleDateString(),
          status: "Confirmed",
          financingRequestId: loanRequest._id,
        });
      } else {
        createdOrder = existingOrder;
      }

      const existingInvoice = await ProjectDocument.findOne({
        financingRequest: loanRequest._id,
        type: "invoice",
      });
      if (!existingInvoice && createdOrder) {
        const approvedQuotation = await ProjectDocument.findOne({
          financingRequest: loanRequest._id,
          type: "quotation",
          status: "approved",
        }).sort({ version: -1 });
        const invoiceLineItems = approvedQuotation?.lineItems?.length
          ? approvedQuotation.lineItems.map((item) => ({
              category: item.category,
              description: item.description,
              quantity: item.quantity,
              unit: item.unit,
              unitPrice: item.unitPrice,
              amount: item.amount,
              source: item.source,
            }))
          : safeItems.map((item) => ({
              category: "other",
              description: item.name,
              quantity: item.quantity,
              unit: "item",
              unitPrice: Number(item.price || 0),
              amount: Number(item.price || 0) * Number(item.quantity || 1),
              source: "confirmed",
            }));
        const invoiceTotal = Number(
          loanRequest.finalProjectCost ?? createdOrder.amount ?? loanRequest.estimatedAmount ?? 0
        );
        createdInvoice = await ProjectDocument.create({
          reference: `BRI-${String(loanRequest.reference || loanRequest._id).replace(/^BRF-/, "")}`,
          financingRequest: loanRequest._id,
          order: createdOrder._id,
          type: "invoice",
          version: 1,
          status: "issued",
          title: approvedQuotation?.title || "BuiltRight financed solar project invoice",
          customer: {
            fullName: loanRequest.customer.fullName,
            email: loanRequest.customer.email,
            phone: loanRequest.customer.phone,
            location: loanRequest.customer.location || "",
          },
          project: approvedQuotation?.project || {
            systemName: safeItems[0]?.name || "Solar power system",
            systemCapacity: safeItems[0]?.capacity || "",
            siteAddress: loanRequest.customer.location || "",
          },
          lineItems: invoiceLineItems,
          subtotal: approvedQuotation?.subtotal ?? invoiceTotal,
          discount: approvedQuotation?.discount ?? 0,
          tax: approvedQuotation?.tax ?? 0,
          total: invoiceTotal,
          equityPercentage: loanRequest.deposit?.percentage || 20,
          equityAmount: loanRequest.deposit?.amount || invoiceTotal * 0.2,
          bankFinanceAmount: loanRequest.bankApplication?.disbursedAmount || invoiceTotal * 0.8,
          terms: "Invoice issued after customer equity and bank disbursement were confirmed.",
          notes: "This invoice forms part of the customer's BuiltRight document history.",
          createdBy: req.admin?.email || "BuiltRight operations",
        });
      } else {
        createdInvoice = existingInvoice;
      }
    }

    loanRequest.status = status;
    loanRequest.statusHistory.push({
      status,
      source: "admin",
      note:
        status === "disbursed"
          ? "Verified bank disbursement received; confirmed order created."
          : "Financing stage updated from the operations portal.",
    });
    await loanRequest.save();

    try {
  const statusMessages = {
    submitted: {
      title: "Financing Request Received",
      message:
        "Your financing request has been received and is awaiting BuiltRight review.",
    },

    "internal-review": {
      title: "BuiltRight Review in Progress",
      message:
        "Our team is reviewing your selected system and preparing the next steps for site inspection.",
    },

    "inspection-scheduled": {
      title: "Site Inspection Scheduled",
      message:
        "Your site inspection has been scheduled. We will confirm the property, cable distance, mounting requirements, and protection accessories.",
    },

    "inspection-completed": {
      title: "Site Inspection Completed",
      message:
        "Your site inspection is complete and BuiltRight is finalizing the installation materials and total project cost.",
    },

    "load-audit-completed": {
      title: "Load Audit Completed",
      message:
        "Your energy-use assessment is complete. BuiltRight is finalizing technical suitability and due diligence.",
    },

    "due-diligence-passed": {
      title: "Pre-Credit Assessment Passed",
      message:
        "Your inspection, load audit, and BuiltRight due-diligence checks passed. We can now prepare the full project quotation.",
    },

    "due-diligence-failed": {
      title: "Pre-Credit Assessment Needs Attention",
      message:
        "One or more inspection or due-diligence items need to be resolved before a final quotation can be prepared.",
    },

    "quotation-draft": {
      title: "Quotation Being Prepared",
      message:
        "BuiltRight is preparing the detailed project quotation from the completed assessment.",
    },

    "quotation-sent": {
      title: "Quotation Sent for Your Approval",
      message:
        "Your detailed project quotation is available in your BuiltRight documents. Review and approve it before starting the bank application.",
    },

    "quotation-approved": {
      title: "Quotation Approved",
      message:
        "Your quotation approval has been recorded. The bank credit application will unlock when the bank-hosted link is available.",
    },

    "quotation-prepared": {
      title: "Final Quotation Prepared",
      message:
        "Your final project quotation has been prepared and is ready for financing handoff.",
    },

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

    "kyc-submitted": {
      title: "KYC Submitted",
      message:
        "Your identity and account information has been submitted to the financing provider for review.",
    },

    "credit-review": {
      title: "Credit Review in Progress",
      message:
        "The financing provider is reviewing your application. BuiltRight will update you when a decision is received.",
    },

    approved: {
      title: "Financing Approved",
      message:
        "Congratulations. Your financing request has been approved successfully.",
    },

    "awaiting-deposit": {
      title: "20% Deposit Required",
      message:
        "Your financing is approved. Please complete the required 20% deposit of the approved total project cost.",
    },

    "deposit-paid": {
      title: "Deposit Confirmed",
      message:
        "Your deposit has been confirmed. We are now awaiting the remaining financing disbursement.",
    },

    "awaiting-disbursement": {
      title: "Awaiting Bank Disbursement",
      message:
        "Your deposit is complete and BuiltRight is awaiting the financing provider's disbursement before releasing the order.",
    },

    disbursed: {
      title: "Financing Disbursed",
      message:
        "The financing disbursement has been confirmed. BuiltRight has created your confirmed order and invoice.",
    },

    "order-created": {
      title: "Order and Invoice Created",
      message:
        "Your confirmed order and invoice have been created. Delivery and installation planning can now begin.",
    },

    "installation-in-progress": {
      title: "Installation in Progress",
      message:
        "Your BuiltRight solar installation is currently in progress.",
    },

    rejected: {
      title: "Financing Request Not Approved",
      message:
        "The financing provider did not approve the application at this time. BuiltRight will contact you about available next steps.",
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
    statusMessages[status] || statusMessages.submitted;

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
            <strong>Selected System Estimate (installation and materials excluded):</strong>
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

    if (status === "disbursed" && createdInvoice && createdInvoice.emailDelivery?.status !== "sent") {
      try {
        const invoicePdf = buildProjectDocumentPdf(createdInvoice);
        const portalUrl = `${process.env.FRONTEND_URL || "https://builtright-frontend.vercel.app"}/customer/documents`;
        await sendEmail({
          to: createdInvoice.customer.email,
          subject: `BuiltRight Project Invoice ${createdInvoice.reference}`,
          html: `
            <div style="font-family:Arial,sans-serif;line-height:1.7;color:#1c2b27;max-width:680px;margin:auto;">
              <h2>Your confirmed BuiltRight project invoice</h2>
              <p>Hello ${escapeHtml(createdInvoice.customer.fullName)},</p>
              <p>Your equity payment and bank disbursement are confirmed. The attached invoice records the full approved project cost.</p>
              <p>Our delivery and installation team will contact you with scheduling and site instructions.</p>
              <p><a href="${portalUrl}" style="display:inline-block;background:#168f82;color:white;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:bold;">View project documents</a></p>
            </div>
          `,
          attachments: [{
            filename: `BuiltRight-Invoice-${createdInvoice.reference}.pdf`,
            content: invoicePdf,
            contentType: "application/pdf",
          }],
        });
        createdInvoice.emailDelivery = { status: "sent", sentAt: new Date(), error: "" };
        createdInvoice.sentAt ||= new Date();
        await createdInvoice.save();
      } catch (invoiceMailError) {
        createdInvoice.emailDelivery = { status: "failed", sentAt: null, error: invoiceMailError.message };
        await createdInvoice.save();
        console.error("CUSTOMER INVOICE EMAIL ERROR:", invoiceMailError.message);
      }
    }

    if (status === "sent-to-bank" && process.env.BANK_APPLICATION_EMAIL) {
      const approvedQuotation = await ProjectDocument.findOne({
        financingRequest: loanRequest._id,
        type: "quotation",
        status: "approved",
      }).sort({ version: -1 });

      if (approvedQuotation && approvedQuotation.bankDelivery?.status !== "sent") {
        try {
          const pdf = buildProjectDocumentPdf(approvedQuotation);
          await sendEmail({
            to: process.env.BANK_APPLICATION_EMAIL,
            subject: `Customer-Approved BuiltRight Quotation ${approvedQuotation.reference}`,
            html: `
              <h2>BuiltRight financing application support document</h2>
              <p><strong>Customer:</strong> ${escapeHtml(loanRequest.customer.fullName)}</p>
              <p><strong>Financing reference:</strong> ${escapeHtml(loanRequest.reference)}</p>
              <p><strong>Quotation:</strong> ${escapeHtml(approvedQuotation.reference)}</p>
              <p><strong>Total project cost:</strong> ${formatDocumentMoney(approvedQuotation.total)}</p>
              <p>The customer-approved quotation is attached.</p>
            `,
            attachments: [
              {
                filename: `BuiltRight-Approved-Quotation-${approvedQuotation.reference}.pdf`,
                content: pdf,
                contentType: "application/pdf",
              },
            ],
          });
          approvedQuotation.bankDelivery = { status: "sent", sentAt: new Date(), error: "" };
          loanRequest.bankApplication.quotationSharedAt = new Date();
          await approvedQuotation.save();
          await loanRequest.save();
        } catch (mailError) {
          approvedQuotation.bankDelivery = {
            status: "failed",
            sentAt: null,
            error: mailError.message,
          };
          await approvedQuotation.save();
          console.error("BANK QUOTATION EMAIL ERROR:", mailError.message);
        }
      }
    }

    return res.json({
      status: true,
      message:
        status === "disbursed"
          ? "Bank disbursement confirmed and order created."
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

const operationsTestScenarios = {
  "builtright-financing": {
    label: "BuiltRight system · bank financing",
    paymentMethod: "bank-financing",
    productSource: "BuiltRight Marketplace",
    steps: [
      ["assign-installer", "Assign installer"],
      ["accept-assignment", "Accept assignment"],
      ["schedule-inspection", "Schedule inspection and fee"],
      ["confirm-inspection-payment", "Confirm inspection payment"],
      ["pass-assessment", "Pass inspection, load audit, and due diligence"],
      ["generate-quotation", "Generate and send quotation"],
      ["approve-quotation", "Record customer quotation approval"],
      ["bank-approved", "Record bank approval and equity"],
      ["disbursement-confirmed", "Confirm disbursement, order, and invoice"],
      ["installation-scheduled", "Schedule installation"],
      ["project-completed", "Complete and commission project"],
    ],
  },
  "external-vendor-financing": {
    label: "External-vendor system · bank financing",
    paymentMethod: "bank-financing",
    productSource: "External Vendor",
    steps: [
      ["assign-installer", "Assign BuiltRight installer"],
      ["accept-assignment", "Accept assignment"],
      ["schedule-inspection", "Schedule inspection and fee"],
      ["confirm-inspection-payment", "Confirm inspection payment"],
      ["pass-assessment", "Verify vendor system and pass all assessments"],
      ["generate-quotation", "Generate BuiltRight project quotation"],
      ["approve-quotation", "Record customer quotation approval"],
      ["bank-approved", "Record bank approval and equity"],
      ["disbursement-confirmed", "Confirm disbursement, order, and invoice"],
      ["installation-scheduled", "Schedule BuiltRight installation"],
      ["project-completed", "Complete and commission project"],
    ],
  },
  "outright-purchase": {
    label: "BuiltRight system · outright purchase",
    paymentMethod: "outright",
    productSource: "BuiltRight Marketplace",
    steps: [
      ["assign-installer", "Assign installer"],
      ["accept-assignment", "Accept assignment"],
      ["schedule-inspection", "Schedule inspection and fee"],
      ["confirm-inspection-payment", "Confirm inspection payment"],
      ["pass-assessment", "Pass inspection, load audit, and due diligence"],
      ["generate-quotation", "Generate and send final quotation"],
      ["approve-quotation", "Record customer quotation approval"],
      ["full-payment-confirmed", "Confirm full payment, order, and invoice"],
      ["installation-scheduled", "Schedule installation"],
      ["project-completed", "Complete and commission project"],
    ],
  },
};

const testStepDetails = (loanRequest) => {
  const scenario = operationsTestScenarios[loanRequest.testRun?.scenario];
  if (!scenario) return { scenario: null, nextStep: null, progress: 0, completed: true };
  const currentStep = Math.max(0, Number(loanRequest.testRun?.currentStep || 0));
  const next = scenario.steps[currentStep];
  return {
    scenario,
    nextStep: next ? { id: next[0], label: next[1] } : null,
    progress: Math.round(((currentStep + 1) / (scenario.steps.length + 1)) * 100),
    completed: currentStep >= scenario.steps.length,
  };
};

const recordTestStep = (loanRequest, stepId, note) => {
  loanRequest.testRun.completedSteps.push(stepId);
  loanRequest.testRun.currentStep += 1;
  loanRequest.testRun.lastCheckedAt = new Date();
  loanRequest.statusHistory.push({
    status: loanRequest.status,
    source: "operations-test",
    note,
  });
};

const createTestOrderAndInvoice = async (loanRequest) => {
  const orderReference = `TEST-${loanRequest.testRun.runId}`;
  let order = await Order.findOne({ reference: orderReference });
  const quotation = await ProjectDocument.findOne({
    financingRequest: loanRequest._id,
    type: "quotation",
    status: "approved",
  }).sort({ version: -1 });
  if (!quotation) throw new Error("An approved quotation is required before creating the test order.");

  if (!order) {
    order = await Order.create({
      orderNumber: generateOrderNumber(),
      reference: orderReference,
      source: loanRequest.paymentMethod === "outright" ? "Manual" : "Financing",
      customer: {
        fullName: loanRequest.customer.fullName,
        email: loanRequest.customer.email,
        phone: loanRequest.customer.phone,
      },
      items: loanRequest.items,
      amount: quotation.total,
      date: new Date().toLocaleDateString("en-GB"),
      status: "Confirmed",
      financingRequestId: loanRequest._id,
    });
  }

  let invoice = await ProjectDocument.findOne({ financingRequest: loanRequest._id, type: "invoice" });
  if (!invoice) {
    invoice = await ProjectDocument.create({
      reference: `BRI-${loanRequest.testRun.runId}`,
      financingRequest: loanRequest._id,
      order: order._id,
      type: "invoice",
      version: 1,
      status: "issued",
      title: "BuiltRight operations test project invoice",
      customer: { ...loanRequest.customer },
      project: quotation.project,
      lineItems: quotation.lineItems,
      subtotal: quotation.subtotal,
      discount: quotation.discount,
      tax: quotation.tax,
      total: quotation.total,
      equityPercentage: quotation.equityPercentage,
      equityAmount: quotation.equityAmount,
      bankFinanceAmount: quotation.bankFinanceAmount,
      terms: "Operations test invoice. No payment is due and no external notification was sent.",
      notes: `Generated by controlled test run ${loanRequest.testRun.runId}.`,
      createdBy: loanRequest.testRun.createdBy || "BuiltRight operations test",
    });
  }
  return { order, invoice };
};

app.get("/api/admin/operations-tests", requireAdminAuth, async (req, res) => {
  try {
    const [activeInstallers, products, testRuns] = await Promise.all([
      User.countDocuments({ role: "installer", isActive: true, "installerProfile.availability": "available" }),
      Product.countDocuments(),
      LoanRequest.find({ "testRun.isTest": true }).sort({ createdAt: -1 }).limit(30).lean(),
    ]);

    const runs = await Promise.all(testRuns.map(async (run) => {
      const details = testStepDetails(run);
      const [documents, order] = await Promise.all([
        ProjectDocument.find({ financingRequest: run._id }).select("type reference status total").sort({ createdAt: -1 }).lean(),
        Order.findOne({ financingRequestId: run._id }).select("orderNumber status amount").lean(),
      ]);
      return {
        ...run,
        scenarioLabel: details.scenario?.label || run.testRun?.scenario,
        nextStep: details.nextStep,
        progress: details.progress,
        completed: details.completed,
        documents,
        order,
      };
    }));

    return res.json({
      status: true,
      readiness: {
        coreReady: activeInstallers > 0 && products > 0,
        checks: [
          { id: "database", label: "Operations database", ready: mongoose.connection.readyState === 1, required: true, detail: "MongoDB persistence" },
          { id: "installers", label: "Active installer", ready: activeInstallers > 0, required: true, detail: `${activeInstallers} available` },
          { id: "products", label: "Product catalogue", ready: products > 0, required: true, detail: `${products} products` },
          { id: "email", label: "Email delivery", ready: Boolean(process.env.RESEND_API_KEY || process.env.SMTP_HOST), required: true, detail: "Suppressed during tests" },
          { id: "bank", label: "Bank API", ready: bankProviderConfigured, required: false, detail: bankProviderConfigured ? "Sandbox configured" : "Manual placeholder" },
          { id: "ashgridx", label: "AshGridX API", ready: ashGridAdapterReady, required: false, detail: ashGridCredentialsPresent ? "Credentials stored; adapter pending" : "Documentation/credentials pending" },
        ],
      },
      scenarios: Object.entries(operationsTestScenarios).map(([id, item]) => ({ id, label: item.label, stepCount: item.steps.length + 1 })),
      runs,
    });
  } catch (error) {
    console.error("GET OPERATIONS TESTS ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load the operations test centre." });
  }
});

app.post("/api/admin/operations-tests", requireAdminAuth, async (req, res) => {
  try {
    const scenario = operationsTestScenarios[req.body.scenario];
    if (!scenario) return res.status(400).json({ status: false, message: "Select a valid test scenario." });
    const runId = `TST-${Date.now().toString(36).toUpperCase()}`;
    const external = scenario.productSource === "External Vendor";
    const financing = scenario.paymentMethod === "bank-financing";
    const loanRequest = await LoanRequest.create({
      reference: `BRF-${runId}`,
      customer: {
        fullName: `Operations Test Customer ${runId.slice(-4)}`,
        email: `operations-${runId.toLowerCase()}@example.invalid`,
        phone: "08000000000",
        location: "BuiltRight controlled test site, Lagos",
      },
      productSource: scenario.productSource,
      paymentMethod: scenario.paymentMethod,
      installationProvider: "BuiltRight Services Ltd",
      financeInstitution: financing ? "RichGreen Microfinance Bank" : "Not applicable — outright payment",
      vendorName: external ? "Controlled External Vendor" : "",
      vendorContact: external ? "test-vendor@example.invalid" : "",
      vendorProductDetails: external ? "10kVA external-vendor hybrid inverter system for technical verification" : "",
      items: [{
        id: external ? "test-external-10kva" : "test-builtright-5kva",
        name: external ? "External Vendor 10kVA Hybrid System" : "BuiltRight 5kVA Hybrid Solar System",
        quantity: 1,
        price: external ? null : 4500000,
        supplier: external ? "Controlled External Vendor" : "BuiltRight Services Ltd",
        manufacturer: external ? "External Vendor" : "BuiltRight approved supplier",
        category: "solar-system",
        type: "Hybrid solar system",
        capacity: external ? "10kVA" : "5kVA",
      }],
      estimatedAmount: external ? null : 4500000,
      consentToShare: true,
      thirdPartyNoticeAccepted: external,
      bankApplication: { provider: financing ? "RichGreen Microfinance Bank" : "", status: financing ? "not-started" : "not-required" },
      deposit: { percentage: financing ? 20 : 100, status: "not-due" },
      status: "submitted",
      statusHistory: [{ status: "submitted", source: "operations-test", note: "Controlled operations test case created; notifications suppressed." }],
      notes: "Controlled operations test record. No money is due and no external notification should be sent.",
      testRun: {
        isTest: true,
        runId,
        scenario: req.body.scenario,
        currentStep: 0,
        completedSteps: ["intake-created"],
        suppressNotifications: true,
        createdBy: req.admin?.email || "BuiltRight admin",
        lastCheckedAt: new Date(),
      },
    });
    return res.status(201).json({ status: true, message: `${scenario.label} test run created.`, loanRequest });
  } catch (error) {
    console.error("CREATE OPERATIONS TEST ERROR:", error.message);
    return res.status(500).json({ status: false, message: error.message || "Could not create the test run." });
  }
});

app.post("/api/admin/operations-tests/:id/next", requireAdminAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findOne({ _id: req.params.id, "testRun.isTest": true });
    if (!loanRequest) return res.status(404).json({ status: false, message: "Test run not found." });
    const details = testStepDetails(loanRequest);
    if (!details.nextStep) return res.status(409).json({ status: false, message: "This test run is already complete." });
    const step = details.nextStep.id;

    if (step === "assign-installer") {
      const installer = await chooseInstaller();
      if (!installer) return res.status(409).json({ status: false, message: "Create or activate an available installer before running this checkpoint." });
      loanRequest.installerAssignment = {
        installer: installer._id,
        installerName: installer.fullName,
        installerEmail: installer.email,
        status: "assigned",
        assignedAt: new Date(),
        history: [{ installer: installer._id, installerName: installer.fullName, status: "assigned", note: "Assigned by controlled operations test.", changedAt: new Date() }],
      };
      loanRequest.status = "internal-review";
      recordTestStep(loanRequest, step, `Test assignment allocated to ${installer.fullName}.`);
    } else if (step === "accept-assignment") {
      loanRequest.installerAssignment.status = "accepted";
      loanRequest.installerAssignment.acceptedAt = new Date();
      loanRequest.installerAssignment.history.push({ installer: loanRequest.installerAssignment.installer, installerName: loanRequest.installerAssignment.installerName, status: "accepted", note: "Test installer accepted assignment.", changedAt: new Date() });
      recordTestStep(loanRequest, step, "Installer acceptance verified.");
    } else if (step === "schedule-inspection") {
      loanRequest.inspection.status = "scheduled";
      loanRequest.inspection.scheduledAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
      loanRequest.inspection.assignee = loanRequest.installerAssignment.installerName;
      loanRequest.inspection.feeAmount = 25000;
      loanRequest.inspection.feeStatus = "payment-requested";
      loanRequest.assessment.status = "in-progress";
      loanRequest.assessment.inspection.status = "scheduled";
      loanRequest.status = "inspection-scheduled";
      loanRequest.installerAssignment.status = "scheduled";
      recordTestStep(loanRequest, step, "Inspection schedule and location-based fee verified.");
    } else if (step === "confirm-inspection-payment") {
      loanRequest.inspection.feeStatus = "payment-confirmed";
      loanRequest.inspection.paymentSubmittedAt = new Date();
      loanRequest.inspection.paymentConfirmedAt = new Date();
      loanRequest.inspection.status = "in-progress";
      loanRequest.status = "under-assessment";
      recordTestStep(loanRequest, step, "Inspection fee proof and confirmation path verified without real payment.");
    } else if (step === "pass-assessment") {
      if (loanRequest.productSource === "External Vendor" && !Number(loanRequest.items?.[0]?.price)) {
        loanRequest.items[0].price = 6500000;
        loanRequest.estimatedAmount = 6500000;
      }
      loanRequest.inspection.status = "completed";
      loanRequest.inspection.completedAt = new Date();
      loanRequest.inspection.propertyType = "Detached duplex";
      loanRequest.inspection.cableDistance = "28 metres";
      loanRequest.inspection.mountingMethod = "Pitched-roof aluminium rail";
      loanRequest.inspection.notes = "Controlled test inspection completed.";
      loanRequest.inspectionCosts = [
        { label: "Installation kit and materials", amount: 420000 },
        { label: "Mounting, cable, DB and protection accessories", amount: 310000 },
      ];
      loanRequest.upfrontCosts = [
        { label: "Standard installation service", amount: 350000, confirmed: true },
        { label: "IoT tracking", amount: 75000, confirmed: true },
        { label: "Maintenance", amount: 120000, confirmed: true },
      ];
      loanRequest.assessment = {
        ...loanRequest.assessment.toObject(),
        status: "passed",
        inspection: { status: "completed", result: "pass", completedAt: new Date(), completedBy: loanRequest.installerAssignment.installerName, notes: "Test inspection passed." },
        loadAudit: { ...loanRequest.assessment.loadAudit.toObject(), status: "completed", result: "pass", peakLoadKw: 3.8, dailyEnergyKwh: 16, criticalLoadKw: 2.4, recommendedInverterKva: loanRequest.productSource === "External Vendor" ? 10 : 5, recommendedBatteryKwh: 15, recommendedSolarKw: 6, backupHours: 8, completedAt: new Date(), completedBy: loanRequest.installerAssignment.installerName, notes: "Controlled load audit passed." },
        dueDiligence: { ...loanRequest.assessment.dueDiligence.toObject(), status: "completed", result: "pass", checklist: [
          { key: "identity-contact", label: "Customer identity and contact verified", status: "pass" },
          { key: "property-authority", label: "Property installation authority verified", status: "pass" },
          { key: "site-access", label: "Site access confirmed", status: "pass" },
          { key: "technical-suitability", label: "Technical suitability confirmed", status: "pass" },
          { key: "financing-consent", label: "Data-sharing consent recorded", status: "pass" },
        ], completedAt: new Date(), completedBy: loanRequest.installerAssignment.installerName, notes: "Controlled due diligence passed." },
      };
      loanRequest.installerAssignment.status = "completed";
      loanRequest.status = "due-diligence-passed";
      recordTestStep(loanRequest, step, "All three mandatory pre-quotation assessments passed.");
    } else if (step === "generate-quotation") {
      const quotation = await autoCreateAndSendQuotation(loanRequest, req.admin?.email || "BuiltRight operations test");
      loanRequest.status = "quotation-sent";
      loanRequest.quotation.status = "sent";
      recordTestStep(loanRequest, step, `Quotation ${quotation.reference} generated; external email suppressed.`);
    } else if (step === "approve-quotation") {
      const quotation = await ProjectDocument.findOne({ financingRequest: loanRequest._id, type: "quotation", status: "sent" }).sort({ version: -1 });
      if (!quotation) throw new Error("A sent test quotation is required before approval.");
      const approvedAt = new Date();
      quotation.status = "approved";
      quotation.customerDecision = { status: "approved", decidedAt: approvedAt, note: "Approved during controlled operations test." };
      await quotation.save();
      loanRequest.quotation.status = "approved";
      loanRequest.quotation.approvedAt = approvedAt;
      loanRequest.bankApplication.customerApprovedAt = approvedAt;
      loanRequest.bankApplication.quotationDocument = quotation._id;
      loanRequest.bankApplication.status = loanRequest.paymentMethod === "outright" ? "not-required" : "ready-for-customer";
      loanRequest.bankApplication.redirectUrl = loanRequest.paymentMethod === "outright" ? "" : `https://bank-sandbox.example.invalid/apply?reference=${loanRequest.reference}`;
      loanRequest.status = "quotation-approved";
      recordTestStep(loanRequest, step, "Customer quotation approval and payment-route unlock verified.");
    } else if (step === "bank-approved") {
      loanRequest.bankApplication.status = "approved";
      loanRequest.bankApplication.externalReference = `BANK-${loanRequest.testRun.runId}`;
      loanRequest.bankApplication.approvedAmount = Number(loanRequest.finalProjectCost || 0) - Number(loanRequest.deposit.amount || 0);
      loanRequest.deposit.status = "paid";
      loanRequest.deposit.paidAt = new Date();
      loanRequest.status = "awaiting-disbursement";
      recordTestStep(loanRequest, step, "Bank approval and customer equity checkpoints verified in sandbox mode.");
    } else if (step === "disbursement-confirmed" || step === "full-payment-confirmed") {
      if (step === "disbursement-confirmed") {
        loanRequest.bankApplication.status = "disbursed";
        loanRequest.bankApplication.disbursedAmount = Number(loanRequest.finalProjectCost || 0) - Number(loanRequest.deposit.amount || 0);
        loanRequest.bankApplication.disbursedAt = new Date();
      } else {
        loanRequest.deposit.status = "paid";
        loanRequest.deposit.amount = loanRequest.finalProjectCost;
        loanRequest.deposit.paidAt = new Date();
      }
      await createTestOrderAndInvoice(loanRequest);
      loanRequest.status = "order-created";
      recordTestStep(loanRequest, step, step === "disbursement-confirmed" ? "Disbursement, confirmed order, and invoice verified." : "Full payment, confirmed order, and invoice verified.");
    } else if (step === "installation-scheduled") {
      loanRequest.status = "installation-scheduled";
      recordTestStep(loanRequest, step, "BuiltRight installation scheduling checkpoint verified.");
    } else if (step === "project-completed") {
      loanRequest.status = "completed";
      const order = await Order.findOne({ financingRequestId: loanRequest._id });
      if (order) { order.status = "Delivered"; await order.save(); }
      recordTestStep(loanRequest, step, "Delivery, installation, testing, and commissioning marked complete.");
    }

    await loanRequest.save();
    const updatedDetails = testStepDetails(loanRequest);
    return res.json({
      status: true,
      message: `${details.nextStep.label} passed.`,
      loanRequest,
      nextStep: updatedDetails.nextStep,
      progress: updatedDetails.progress,
      completed: updatedDetails.completed,
    });
  } catch (error) {
    console.error("ADVANCE OPERATIONS TEST ERROR:", error.message);
    return res.status(500).json({ status: false, message: error.message || "The test checkpoint failed." });
  }
});

app.delete("/api/admin/operations-tests/:id", requireAdminAuth, async (req, res) => {
  try {
    const testRun = await LoanRequest.findOne({ _id: req.params.id, "testRun.isTest": true });
    if (!testRun) return res.status(404).json({ status: false, message: "Test run not found." });
    await Promise.all([
      ProjectDocument.deleteMany({ financingRequest: testRun._id }),
      Order.deleteMany({ financingRequestId: testRun._id }),
      LoanRequest.deleteOne({ _id: testRun._id, "testRun.isTest": true }),
    ]);
    return res.json({ status: true, message: `Test run ${testRun.testRun.runId} and its generated test records were removed.` });
  } catch (error) {
    console.error("DELETE OPERATIONS TEST ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not remove the test run." });
  }
});

/* =========================
   ADMIN DASHBOARD
========================= */

app.get("/api/admin/dashboard-stats", requireAdminAuth, async (req, res) => {
  try {
    const productionFilter = { "testRun.isTest": { $ne: true } };
    const stageGroups = {
      newRequests: ["submitted", "internal-review", "pending", "contacted"],
      inspection: ["inspection-scheduled", "inspection-completed"],
      quotation: ["load-audit-completed", "due-diligence-passed", "quotation-draft", "quotation-sent", "quotation-approved"],
      bankReview: ["sent-to-bank", "kyc-submitted", "credit-review"],
      approved: ["approved", "awaiting-deposit", "deposit-paid", "awaiting-disbursement"],
      disbursed: ["disbursed", "order-created", "installation-scheduled", "installation-in-progress", "completed"],
    };
    const [
      totalProducts,
      totalOrders,
      totalLoanRequests,
      totalCustomers,
      recentLoanRequests,
      devices,
      deviceAlerts,
      ...stageCounts
    ] = await Promise.all([
      Product.countDocuments(),
      Order.countDocuments(),
      LoanRequest.countDocuments(productionFilter),
      User.countDocuments({ role: "customer" }),
      LoanRequest.find(productionFilter).sort({ updatedAt: -1 }).limit(6).lean(),
      Device.find().sort({ updatedAt: -1 }).limit(6).lean(),
      DeviceAlert.find({ status: { $in: ["open", "acknowledged"] } }).sort({ occurredAt: -1 }).limit(8).lean(),
      ...Object.values(stageGroups).map((statuses) => LoanRequest.countDocuments({ ...productionFilter, status: { $in: statuses } })),
    ]);
    const stageSummary = Object.keys(stageGroups).reduce((result, key, index) => ({ ...result, [key]: stageCounts[index] }), {});
    const pendingLoanRequests = stageSummary.newRequests;
    const approvedLoans = stageSummary.approved + stageSummary.disbursed;
    const inspectionsDue = await LoanRequest.countDocuments({
      ...productionFilter,
      status: { $in: ["submitted", "internal-review", "inspection-scheduled"] },
    });
    const activeProjects = await LoanRequest.countDocuments({
      ...productionFilter,
      status: { $in: ["quotation-approved", "sent-to-bank", "kyc-submitted", "credit-review", "approved", "awaiting-deposit", "deposit-paid", "awaiting-disbursement", "disbursed", "order-created", "installation-scheduled", "installation-in-progress"] },
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
        inspectionsDue,
        activeProjects,
        openDeviceAlerts: deviceAlerts.length,
      },
      stageSummary,
      recentLoanRequests,
      devices,
      deviceAlerts,
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
    const customer = await User.findOne({
      _id: req.params.id,
      role: "customer",
    }).lean();

    if (!customer) {
      return res.status(404).json({
        status: false,
        message: "Customer not found.",
      });
    }

    const customerEmail = String(customer.email || "").toLowerCase();
    const [loanRequests, devices, orders] = await Promise.all([
      LoanRequest.find({ "customer.email": customerEmail }).select("_id").lean(),
      Device.find({
        $or: [
          { customer: customer._id },
          { "customerSnapshot.email": customerEmail },
        ],
      }).select("_id").lean(),
      Order.find({ "customer.email": customerEmail }).select("_id financingRequestId").lean(),
    ]);
    const loanRequestIds = loanRequests.map((item) => item._id);
    const deviceIds = devices.map((item) => item._id);
    const orderIds = orders.map((item) => item._id);

    await Promise.all([
      ProjectDocument.deleteMany({
        $or: [
          ...(loanRequestIds.length ? [{ financingRequest: { $in: loanRequestIds } }] : []),
          ...(orderIds.length ? [{ order: { $in: orderIds } }] : []),
        ],
      }),
      Order.deleteMany({
        $or: [
          { "customer.email": customerEmail },
          ...(loanRequestIds.length ? [{ financingRequestId: { $in: loanRequestIds } }] : []),
        ],
      }),
      LoanRequest.deleteMany({ _id: { $in: loanRequestIds } }),
      DeviceCommand.deleteMany({ device: { $in: deviceIds } }),
      DeviceAlert.deleteMany({ device: { $in: deviceIds } }),
      Device.deleteMany({ _id: { $in: deviceIds } }),
      User.deleteOne({ _id: customer._id, role: "customer" }),
    ]);

    return res.json({
      status: true,
      message: "Customer and all linked financing, order, document, device, alert, and command records were permanently deleted.",
    });
  } catch (error) {
    console.error("DELETE CUSTOMER ERROR:", error.message);

    return res.status(500).json({
      status: false,
      message: "Failed to delete customer.",
    });
  }
});

app.post("/api/admin/reset-operational-data", requireAdminAuth, async (req, res) => {
  try {
    if (String(req.body.confirmation || "").trim() !== "RESET OPERATIONS") {
      return res.status(400).json({ status: false, message: "Type RESET OPERATIONS to confirm this irreversible reset." });
    }

    const [customers, loanRequests, orders, documents, devices, alerts, commands] = await Promise.all([
      User.countDocuments({ role: "customer" }),
      LoanRequest.countDocuments(),
      Order.countDocuments(),
      ProjectDocument.countDocuments(),
      Device.countDocuments(),
      DeviceAlert.countDocuments(),
      DeviceCommand.countDocuments(),
    ]);

    await Promise.all([
      ProjectDocument.deleteMany({}),
      Order.deleteMany({}),
      LoanRequest.deleteMany({}),
      DeviceCommand.deleteMany({}),
      DeviceAlert.deleteMany({}),
      Device.deleteMany({}),
      User.deleteMany({ role: "customer" }),
    ]);

    return res.json({
      status: true,
      message: "Operational data reset complete. Products, installers, and admin accounts were preserved.",
      deleted: { customers, loanRequests, orders, documents, devices, alerts, commands },
    });
  } catch (error) {
    console.error("RESET OPERATIONAL DATA ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not reset operational data." });
  }
});

app.get("/api/admin/installers", requireAdminAuth, async (req, res) => {
  try {
    const installers = await User.find({ role: "installer" }).select("-password -installerProfile.invitationToken").sort({ createdAt: 1 }).lean();
    const installersWithWorkload = await Promise.all(installers.map(async (installer) => ({
      ...installer,
      activeAssignments: await LoanRequest.countDocuments({
        "installerAssignment.installer": installer._id,
        "installerAssignment.status": { $in: activeInstallerStatuses },
        "testRun.isTest": { $ne: true },
      }),
    })));
    return res.json({ status: true, installers: installersWithWorkload });
  } catch (error) {
    console.error("GET INSTALLERS ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load installers." });
  }
});

app.get("/api/admin/installers/:id/assignments", requireAdminAuth, async (req, res) => {
  try {
    const installer = await User.findOne({ _id: req.params.id, role: "installer" })
      .select("fullName email isActive installerProfile.availability")
      .lean();
    if (!installer) return res.status(404).json({ status: false, message: "Installer not found." });

    const assignments = await LoanRequest.find({
      "installerAssignment.installer": installer._id,
      "testRun.isTest": { $ne: true },
    })
      .select("reference customer items productSource paymentMethod status createdAt updatedAt inspection assessment installerAssignment")
      .sort({ updatedAt: -1 })
      .lean();

    return res.json({ status: true, installer, assignments });
  } catch (error) {
    console.error("GET INSTALLER ASSIGNMENTS ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load the installer's workboard." });
  }
});

app.delete("/api/admin/installers/:id", requireAdminAuth, async (req, res) => {
  try {
    const installer = await User.findOne({ _id: req.params.id, role: "installer" });
    if (!installer) return res.status(404).json({ status: false, message: "Installer not found." });

    const activeAssignments = await LoanRequest.countDocuments({
      "installerAssignment.installer": installer._id,
      "installerAssignment.status": { $in: activeInstallerStatuses },
      "testRun.isTest": { $ne: true },
    });
    if (activeAssignments > 0) {
      return res.status(409).json({
        status: false,
        message: `This installer has ${activeAssignments} active assignment${activeAssignments === 1 ? "" : "s"}. Reassign or complete the work before deleting the account.`,
      });
    }

    await User.deleteOne({ _id: installer._id });
    return res.json({ status: true, message: "Installer account deleted successfully." });
  } catch (error) {
    console.error("DELETE INSTALLER ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not delete installer." });
  }
});

app.post("/api/admin/installers", requireAdminAuth, async (req, res) => {
  try {
    const { fullName, email } = req.body;
    if (!fullName || !email) return res.status(400).json({ status: false, message: "Installer name and email are required." });
    const existing = await User.findOne({ email: String(email).toLowerCase() });
    if (existing) return res.status(409).json({ status: false, message: "An account already uses this email address." });
    const installer = await makeInstallerInvite({ fullName: String(fullName).trim(), email: String(email).toLowerCase().trim() });
    return res.status(201).json({ status: true, message: "Installer invitation email sent.", installer: { id: installer._id, fullName: installer.fullName, email: installer.email } });
  } catch (error) {
    console.error("CREATE INSTALLER ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not create installer." });
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

app.post(
  "/api/customer/loan-requests/:id/inspection-payment-proof",
  requireCustomerAuth,
  upload.single("proof"),
  async (req, res) => {
    try {
      const loanRequest = await LoanRequest.findOne({ _id: req.params.id, "customer.email": req.user.email });
      if (!loanRequest) return res.status(404).json({ status: false, message: "Financing request not found." });
      if (loanRequest.inspection?.feeStatus !== "payment-requested") {
        return res.status(409).json({ status: false, message: "Inspection payment proof is not currently required for this request." });
      }
      if (!req.file || !/^image\/(jpeg|png|webp)$|^application\/pdf$/.test(req.file.mimetype)) {
        return res.status(400).json({ status: false, message: "Upload a PDF, JPG, PNG, or WEBP payment proof." });
      }
      if (req.file.size > 8 * 1024 * 1024) {
        return res.status(400).json({ status: false, message: "Payment proof must be 8 MB or smaller." });
      }
      const result = await cloudinary.uploader.upload(
        `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`,
        { folder: "builtright/inspection-payment-proofs", resource_type: "auto" }
      );
      loanRequest.inspection.paymentProof = {
        url: result.secure_url,
        publicId: result.public_id,
        fileName: req.file.originalname,
        uploadedAt: new Date(),
      };
      loanRequest.inspection.paymentSubmittedAt = new Date();
      loanRequest.inspection.feeStatus = "proof-submitted";
      loanRequest.statusHistory.push({ status: loanRequest.status, source: "customer", note: "Customer uploaded proof of the inspection-fee payment." });
      await loanRequest.save();

      if (loanRequest.installerAssignment?.installerEmail) {
        try {
          await sendEmail({
            to: loanRequest.installerAssignment.installerEmail,
            subject: `Inspection payment proof submitted - ${loanRequest.reference}`,
            html: `<h2>Inspection payment proof submitted</h2><p>${safeHtml(loanRequest.customer.fullName)} has uploaded proof of payment for the inspection fee.</p><p>Sign in to your installer profile to confirm receipt and begin the inspection process.</p><p><a href="${frontendUrl()}/installer/assignments">Open installer profile</a></p>`,
          });
        } catch (mailError) {
          console.error("INSPECTION PROOF NOTIFICATION ERROR:", mailError.message);
        }
      }
      return res.json({ status: true, message: "Payment proof uploaded. Your installer will confirm receipt before beginning the inspection.", loanRequest });
    } catch (error) {
      console.error("UPLOAD INSPECTION PAYMENT PROOF ERROR:", error.message);
      return res.status(500).json({ status: false, message: "Could not upload the inspection payment proof." });
    }
  }
);

app.get("/api/customer/documents", requireCustomerAuth, async (req, res) => {
  try {
    const documents = await ProjectDocument.find({
      "customer.email": req.user.email,
    })
      .sort({ createdAt: -1 })
      .lean();

    const financingIds = [...new Set(documents.map((document) => String(document.financingRequest)))];
    const financingRequests = await LoanRequest.find({ _id: { $in: financingIds } })
      .select("reference status quotation bankApplication deposit finalProjectCost paymentMethod installationProvider productSource")
      .lean();
    const financingById = new Map(financingRequests.map((item) => [String(item._id), item]));

    return res.json({
      status: true,
      documents: documents.map((document) => ({
        ...document,
        financing: financingById.get(String(document.financingRequest)) || null,
      })),
    });
  } catch (error) {
    console.error("CUSTOMER DOCUMENTS ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load your documents." });
  }
});

app.get("/api/customer/documents/:id/download", requireCustomerAuth, async (req, res) => {
  try {
    const projectDocument = await ProjectDocument.findOne({
      _id: req.params.id,
      "customer.email": req.user.email,
    }).lean();
    if (!projectDocument) {
      return res.status(404).json({ status: false, message: "Document not found." });
    }

    const pdf = buildProjectDocumentPdf(projectDocument);
    const documentLabel = projectDocument.type === "invoice" ? "Invoice" : "Quotation";
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="BuiltRight-${documentLabel}-${projectDocument.reference}.pdf"`
    );
    return res.send(pdf);
  } catch (error) {
    console.error("DOWNLOAD CUSTOMER DOCUMENT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not download the document." });
  }
});

app.post("/api/customer/quotations/:id/approve", requireCustomerAuth, async (req, res) => {
  try {
    const quotation = await ProjectDocument.findOne({
      _id: req.params.id,
      type: "quotation",
      "customer.email": req.user.email,
    });
    if (!quotation) {
      return res.status(404).json({ status: false, message: "Quotation not found." });
    }
    if (quotation.status !== "sent") {
      return res.status(409).json({
        status: false,
        message: "Only a quotation sent by BuiltRight can be approved.",
      });
    }

    const loanRequest = await LoanRequest.findById(quotation.financingRequest);
    if (!loanRequest) {
      return res.status(404).json({ status: false, message: "Financing request not found." });
    }

    const approvedAt = new Date();
    quotation.status = "approved";
    quotation.customerDecision = {
      status: "approved",
      decidedAt: approvedAt,
      note: String(req.body.note || "Customer approved the quotation in the BuiltRight portal."),
    };

    loanRequest.quotation ||= {};
    loanRequest.bankApplication ||= {};
    const isOutright = loanRequest.paymentMethod === "outright";
    const bankApplicationUrl = isOutright
      ? ""
      : (loanRequest.bankApplication?.redirectUrl || process.env.BANK_APPLICATION_URL || "");
    const bankApplicationEmail = isOutright ? "" : (process.env.BANK_APPLICATION_EMAIL || "");
    loanRequest.quotation.status = "approved";
    loanRequest.quotation.document = quotation._id;
    loanRequest.quotation.reference = quotation.reference;
    loanRequest.quotation.approvedAt = approvedAt;
    loanRequest.bankApplication.redirectUrl = bankApplicationUrl;
    loanRequest.bankApplication.quotationDocument = quotation._id;
    loanRequest.bankApplication.customerApprovedAt = approvedAt;
    loanRequest.bankApplication.status = isOutright
      ? "not-required"
      : (bankApplicationUrl ? "ready-for-customer" : "awaiting-bank-link");
    loanRequest.status = "quotation-approved";
    loanRequest.statusHistory.push({
      status: "quotation-approved",
      source: "customer",
      note: isOutright
        ? `Customer approved quotation ${quotation.reference}; final outright-payment invoice is required.`
        : `Customer approved quotation ${quotation.reference}.`,
    });

    if (bankApplicationEmail) {
      quotation.bankDelivery.status = "pending";
      try {
        const pdf = buildProjectDocumentPdf(quotation);
        await sendEmail({
          to: bankApplicationEmail,
          subject: `Customer-Approved BuiltRight Quotation ${quotation.reference}`,
          html: `
            <div style="font-family:Arial,sans-serif;line-height:1.7;color:#1c2b27;">
              <h2>Customer-approved solar financing quotation</h2>
              <p><strong>Customer:</strong> ${escapeHtml(quotation.customer.fullName)}</p>
              <p><strong>Email:</strong> ${escapeHtml(quotation.customer.email)}</p>
              <p><strong>Phone:</strong> ${escapeHtml(quotation.customer.phone)}</p>
              <p><strong>BuiltRight financing reference:</strong> ${escapeHtml(loanRequest.reference)}</p>
              <p><strong>Quotation:</strong> ${escapeHtml(quotation.reference)}</p>
              <p><strong>Total project cost:</strong> ${formatDocumentMoney(quotation.total)}</p>
              <p><strong>Customer equity:</strong> ${formatDocumentMoney(quotation.equityAmount)}</p>
              <p><strong>Requested bank finance:</strong> ${formatDocumentMoney(quotation.bankFinanceAmount)}</p>
              <p>The approved quotation is attached to support the customer's credit and KYC application.</p>
            </div>
          `,
          attachments: [
            {
              filename: `BuiltRight-Approved-Quotation-${quotation.reference}.pdf`,
              content: pdf,
              contentType: "application/pdf",
            },
          ],
        });
        quotation.bankDelivery = { status: "sent", sentAt: new Date(), error: "" };
        loanRequest.bankApplication.quotationSharedAt = new Date();
      } catch (mailError) {
        quotation.bankDelivery = { status: "failed", sentAt: null, error: mailError.message };
      }
    }

    await quotation.save();
    await loanRequest.save();

    return res.json({
      status: true,
      message: isOutright
        ? "Quotation approved. BuiltRight will issue your final outright-payment invoice."
        : (bankApplicationUrl
          ? "Quotation approved. Your bank credit application is now available."
          : "Quotation approved. BuiltRight is awaiting the bank's hosted application link."),
      quotation,
      bankApplication: {
        ready: Boolean(bankApplicationUrl),
        url: bankApplicationUrl,
        status: loanRequest.bankApplication.status,
      },
    });
  } catch (error) {
    console.error("APPROVE QUOTATION ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not approve the quotation." });
  }
});

app.post("/api/customer/quotations/:id/request-changes", requireCustomerAuth, async (req, res) => {
  try {
    const note = String(req.body.note || "").trim();
    if (!note) {
      return res.status(400).json({ status: false, message: "Please describe the requested changes." });
    }
    const quotation = await ProjectDocument.findOne({
      _id: req.params.id,
      type: "quotation",
      "customer.email": req.user.email,
    });
    if (!quotation) {
      return res.status(404).json({ status: false, message: "Quotation not found." });
    }
    if (quotation.status !== "sent") {
      return res.status(409).json({ status: false, message: "This quotation is not awaiting a decision." });
    }

    quotation.status = "changes-requested";
    quotation.customerDecision = { status: "changes-requested", decidedAt: new Date(), note };
    await quotation.save();

    const loanRequest = await LoanRequest.findById(quotation.financingRequest);
    if (loanRequest) {
      loanRequest.quotation.status = "changes-requested";
      loanRequest.quotation.changesRequestedAt = new Date();
      loanRequest.status = "quotation-draft";
      loanRequest.statusHistory.push({
        status: "quotation-draft",
        source: "customer",
        note: `Customer requested changes to ${quotation.reference}: ${note}`,
      });
      await loanRequest.save();
    }

    try {
      await sendEmail({
        to: process.env.ADMIN_ALERT_EMAIL || process.env.SMTP_USER,
        subject: `Quotation Changes Requested - ${quotation.reference}`,
        html: `<p>${escapeHtml(quotation.customer.fullName)} requested changes to ${escapeHtml(quotation.reference)}.</p><p>${escapeHtml(note)}</p>`,
      });
    } catch (mailError) {
      console.error("QUOTATION CHANGE EMAIL ERROR:", mailError.message);
    }

    return res.json({ status: true, message: "Your change request was sent to BuiltRight.", quotation });
  } catch (error) {
    console.error("REQUEST QUOTATION CHANGES ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not send the change request." });
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
