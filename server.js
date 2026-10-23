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
import TrainingSettings from "./models/TrainingSettings.js";
import AdminCredential from "./models/AdminCredential.js";
import { accountingRoutes } from "./accounting/routes.js";
import sendEmail from "./utils/sendEmail.js";
import { builtRightEnergyLogoDataUri } from "./utils/invoiceBrandAssets.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());

const getAshGridHeader = (req, name, fallback) =>
  req.get(name || fallback) || req.get(fallback) || "";

const ashGridWebhookSecret = () => process.env.ASHGRIDX_WEBHOOK_SECRET || "";

const verifyAshGridWebhook = (rawBody, signature, timestamp) => {
  const secret = ashGridWebhookSecret();
  if (!secret) return { valid: false, code: "not-configured" };
  if (!rawBody || !signature) return { valid: false, code: "missing-signature" };

  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return { valid: false, code: "invalid-json" };
  }
  const effectiveTimestamp = timestamp || parsed.timestamp;
  if (!effectiveTimestamp) return { valid: false, code: "missing-timestamp" };

  const timestampNumber = Number(effectiveTimestamp);
  if (!Number.isFinite(timestampNumber)) return { valid: false, code: "invalid-timestamp" };
  if (Math.abs(Math.floor(Date.now() / 1000) - timestampNumber) > 120) {
    return { valid: false, code: "stale-timestamp" };
  }

  // AshGridX signs the exact event/timestamp/data envelope. The raw body is
  // retained for the audit fingerprint and is never trusted before this check.
  const signedPayload = JSON.stringify({
    event: parsed.event,
    timestamp: String(effectiveTimestamp),
    data: parsed.data,
  });
  const expected = crypto.createHmac("sha256", secret).update(signedPayload).digest("hex");
  const supplied = String(signature).replace(/^sha256=/i, "").trim();
  const expectedBuffer = Buffer.from(expected, "utf8");
  const suppliedBuffer = Buffer.from(supplied, "utf8");
  const valid = expectedBuffer.length === suppliedBuffer.length && crypto.timingSafeEqual(expectedBuffer, suppliedBuffer);
  return { valid, code: valid ? "ok" : "invalid-signature", parsed, timestamp: timestampNumber };
};

const ashGridEventDeviceNumber = (payload = {}) =>
  payload.deviceNumber || payload.deviceId || payload.customerDeviceId || payload.data?.deviceNumber || payload.data?.deviceId || payload.data?.customerDeviceId;

const processAshGridXEvent = async ({ payload, rawBody, source = "provider-webhook" }) => {
  const eventName = String(payload.event || payload.type || payload.data?.event || "UNKNOWN").toUpperCase();
  const data = payload.data && typeof payload.data === "object" ? payload.data : payload;
  const identifier = ashGridEventDeviceNumber(data) || ashGridEventDeviceNumber(payload);
  const fingerprint = `ashgridx-${crypto.createHash("sha256").update(rawBody || JSON.stringify(payload)).digest("hex")}`;
  const duplicate = await DeviceAlert.findOne({ providerEventId: fingerprint });
  if (duplicate) return { duplicate: true, alert: duplicate };

  const device = await resolveDevice(identifier);
  if (!device) return { ignored: true, reason: "device-not-registered", identifier, eventName };

  const isTamper = ["BYPASS", "TAMPER", "CABLE_DISCONNECTED", "PROTECTION_BYPASS"].includes(eventName);
  const isRestored = ["TAMPER_RESTORED", "PROTECTION_RESTORED", "NORMAL", "CLEAR"].includes(eventName);
  const isOffline = ["DEVICE_OFFLINE", "DISCONNECTED"].includes(eventName);
  const occurredAt = payload.timestamp ? new Date(Number(payload.timestamp) * 1000) : new Date();

  if (isTamper) {
    device.tamper = {
      status: "confirmed",
      eventType: "BYPASS",
      detectedAt: occurredAt,
      acknowledgedAt: null,
      notes: "AshGridX reported a protection bypass/cable disconnection.",
    };
    device.inverterState = "off";
  } else if (isRestored) {
    device.tamper = {
      status: "clear",
      eventType: eventName,
      detectedAt: device.tamper?.detectedAt || null,
      acknowledgedAt: device.tamper?.acknowledgedAt || null,
      notes: "AshGridX reported that the protection condition has cleared.",
    };
  }
  if (isOffline) device.connectivity = "offline";
  if (["DEVICE_ONLINE", "CONNECTED", "CONNECTIVITY_RESTORED"].includes(eventName)) {
    device.connectivity = "online";
    device.lastSeenAt = occurredAt;
  }
  device.lastProviderSyncAt = new Date();
  await device.save();

  const alert = await DeviceAlert.create({
    reference: generateOperationsReference("BRALT"),
    device: device._id,
    deviceReference: device.reference,
    providerEventId: fingerprint,
    type: isTamper ? "cable-disconnected" : isOffline ? "offline" : isRestored ? "connectivity-restored" : "other",
    severity: isTamper ? "critical" : isOffline ? "warning" : "info",
    status: "open",
    source,
    occurredAt,
    title: isTamper ? "AshGridX BYPASS / tamper detected" : `AshGridX ${eventName.toLowerCase().replaceAll("_", " ")}`,
    detail: isTamper
      ? "The inverter protection circuit reported a cable disconnection. The device should be investigated at the assigned site."
      : String(data.reason || data.message || "Provider event received and recorded."),
    evidence: { event: eventName, deviceNumber: identifier, payload },
  });
  return { alert, device, eventName };
};

// Provider webhook routes keep the raw request body available for HMAC
// verification. They return a clear configuration response until a secret is
// supplied, while fully processing signed pilot events once enabled.
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
  async (req, res) => {
    const signatureHeader = process.env.ASHGRIDX_WEBHOOK_SIGNATURE_HEADER || "x-ashgridx-signature";
    const timestampHeader = process.env.ASHGRIDX_WEBHOOK_TIMESTAMP_HEADER || "x-ashgridx-timestamp";
    const signature = getAshGridHeader(req, signatureHeader, "x-ashgridx-signature")
      || req.get("x-signature")
      || req.get("x-webhook-signature");
    const timestamp = getAshGridHeader(req, timestampHeader, "x-ashgridx-timestamp")
      || req.get("x-timestamp");
    const verification = verifyAshGridWebhook(req.body, signature, timestamp);
    if (verification.code === "not-configured") {
      return res.status(503).json({ status: false, code: "ASHGRIDX_WEBHOOK_NOT_CONFIGURED", message: "AshGridX webhook secret is not configured." });
    }
    if (!verification.valid) {
      return res.status(401).json({ status: false, code: `ASHGRIDX_WEBHOOK_${verification.code.toUpperCase()}`, message: "AshGridX webhook signature could not be verified." });
    }
    try {
      const result = await processAshGridXEvent({ payload: verification.parsed, rawBody: req.body });
      return res.status(200).json({ status: true, received: true, ...result });
    } catch (error) {
      console.error("AshGridX webhook processing error:", error);
      return res.status(500).json({ status: false, message: "AshGridX event could not be recorded." });
    }
  }
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

const productionFrontendUrl = "https://www.builtrightltd.com";

const frontendUrl = () => {
  const configuredUrl = String(process.env.FRONTEND_URL || "")
    .trim()
    .replace(/\/+$/, "");

  if (!configuredUrl) return productionFrontendUrl;

  try {
    const hostname = new URL(configuredUrl).hostname.toLowerCase();
    if (hostname.endsWith(".vercel.app")) {
      console.warn("FRONTEND_URL points to Vercel; using the BuiltRight domain instead.");
      return productionFrontendUrl;
    }
  } catch {
    console.warn("FRONTEND_URL is invalid; using the BuiltRight domain instead.");
    return productionFrontendUrl;
  }

  return configuredUrl;
};

const inspectionPaymentDetails = {
  bank: process.env.INSPECTION_PAYMENT_BANK || "FCMB",
  accountNumber: process.env.INSPECTION_PAYMENT_ACCOUNT || "2008839924",
  accountName: process.env.INSPECTION_PAYMENT_ACCOUNT_NAME || "BuiltRight Services Ltd",
};

const safeHtml = (value = "") => String(value)
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#039;");

const passwordResetTokenHash = (rawToken = "") =>
  crypto.createHash("sha256").update(String(rawToken)).digest("hex");

const passwordResetLoginPaths = {
  customer: "/auth",
  installer: "/installer/login",
  learner: "/learner/login",
  sales: "/sales/login",
  accountant: "/accounting/login",
};

const passwordResetRoleLabels = {
  customer: "customer",
  installer: "installer",
  learner: "learner",
  sales: "sales team",
  accountant: "accountant",
};

const formatNaira = (amount) => `₦${Number(amount || 0).toLocaleString("en-NG", { maximumFractionDigits: 0 })}`;

const normalizeSmsPhone = (value = "") => {
  const digits = String(value).replace(/\D/g, "");
  if (digits.startsWith("234")) return digits;
  if (digits.startsWith("0")) return `234${digits.slice(1)}`;
  return digits.length === 10 ? `234${digits}` : digits;
};

const sendSms = async ({ to, message }) => {
  const baseUrl = String(process.env.TERMII_BASE_URL || "").replace(/\/$/, "");
  const apiKey = process.env.TERMII_API_KEY;
  const phone = normalizeSmsPhone(to);
  if (!baseUrl || !apiKey) {
    console.warn("SMS NOT SENT: TERMII_BASE_URL and TERMII_API_KEY are not configured.");
    return { status: "not-configured" };
  }
  if (!phone) return { status: "missing-phone" };
  const response = await axios.post(`${baseUrl}/api/sms/send`, {
    api_key: apiKey,
    to: phone,
    from: process.env.TERMII_SENDER_ID || "BuiltRight",
    sms: String(message),
    channel: process.env.TERMII_CHANNEL || "dnd",
    type: "plain",
  });
  return response.data;
};

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
    phone: installer.phone || "",
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

const sendLearnerInviteEmail = async (user, rawToken) => {
  const activationUrl = `${frontendUrl()}/learner/activate?token=${rawToken}`;
  try {
    await sendEmail({
      to: user.email,
      subject: "Welcome to BuiltRight Solar Installation Training",
      html: `<h2>Welcome to BuiltRight Solar Installation Training</h2><p>Hello ${safeHtml(user.fullName)},</p><p>Your learner account has been created for the active virtual training cohort. Set a secure password to access your curriculum, training brochure, live class link, and session resources.</p><p><a href="${activationUrl}">Set your learner password</a></p><p>This secure invitation expires in 7 days.</p>`,
    });
    user.learnerProfile.invitationEmailSentAt = new Date();
    await user.save();
    return true;
  } catch (mailError) {
    console.error("LEARNER INVITE EMAIL ERROR:", mailError.message);
    return false;
  }
};

const makeLearnerInvite = async (learner) => {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const temporaryPassword = crypto.randomBytes(24).toString("base64url");
  const user = await User.create({
    fullName: learner.fullName,
    email: learner.email,
    phone: learner.phone || "",
    password: await bcrypt.hash(temporaryPassword, 10),
    role: "learner",
    isActive: false,
    learnerProfile: {
      invitationToken: rawToken,
      invitationExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      invitedAt: new Date(),
      cohortName: learner.cohortName || "BuiltRight Solar Installation Training",
      cohortStart: learner.cohortStart || null,
      cohortEnd: learner.cohortEnd || null,
      enrollmentStatus: "invited",
    },
  });
  await sendLearnerInviteEmail(user, rawToken);
  return user;
};

const sendSalesInviteEmail = async (user, rawToken) => {
  const activationUrl = `${frontendUrl()}/sales/activate?token=${rawToken}`;
  try {
    await sendEmail({
      to: user.email,
      subject: "Welcome to BuiltRight Sales Operations",
      html: `<h2>Welcome to BuiltRight Sales Operations</h2><p>Hello ${safeHtml(user.fullName)},</p><p>Your sales account is ready. Set a secure password to register customers received through WhatsApp or direct enquiries, set assessment fees, assign installers, review field reports, and prepare customer quotations.</p><p><a href="${activationUrl}">Activate your sales account</a></p><p>This secure invitation expires in 7 days.</p>`,
    });
    user.salesProfile.invitationEmailSentAt = new Date();
    await user.save();
    return true;
  } catch (mailError) {
    console.error("SALES INVITE EMAIL ERROR:", mailError.message);
    return false;
  }
};

const makeSalesInvite = async ({ fullName, email, phone = "" }) => {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const temporaryPassword = crypto.randomBytes(24).toString("base64url");
  const user = await User.create({
    fullName,
    email,
    phone,
    password: await bcrypt.hash(temporaryPassword, 10),
    role: "sales",
    isActive: false,
    salesProfile: {
      invitationToken: rawToken,
      invitationExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      invitedAt: new Date(),
    },
  });
  await sendSalesInviteEmail(user, rawToken);
  return user;
};

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected");
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

const requireOperationsAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ status: false, message: "Unauthorized" });
    }
    const decoded = jwt.verify(authHeader.split(" ")[1], process.env.JWT_SECRET);
    if (!["admin", "sales"].includes(decoded.role)) {
      return res.status(403).json({ status: false, message: "BuiltRight operations access required." });
    }
    if (decoded.role === "sales") {
      const salesUser = await User.findOne({ _id: decoded.id, role: "sales", isActive: true }).select("_id").lean();
      if (!salesUser) return res.status(403).json({ status: false, message: "This sales account is no longer active." });
    }
    req.admin = decoded;
    req.staff = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ status: false, message: "Invalid or expired token." });
  }
};

const requireCustomerAuth = async (req, res, next) => {
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
    const customer = await User.findOne({ _id: decoded.id, role: "customer", isActive: true }).select("_id").lean();
    if (!customer) return res.status(403).json({ status: false, message: "This customer account is no longer active." });

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      status: false,
      message: "Invalid or expired token.",
    });
  }
};

app.use("/api", accountingRoutes(requireAdminAuth));

const requireInstallerAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ status: false, message: "Unauthorized" });
    }
    const decoded = jwt.verify(authHeader.split(" ")[1], process.env.JWT_SECRET);
    if (decoded.role !== "installer") {
      return res.status(403).json({ status: false, message: "Installer access required." });
    }
    const installer = await User.findOne({ _id: decoded.id, role: "installer", isActive: true }).select("_id").lean();
    if (!installer) return res.status(403).json({ status: false, message: "This installer account is no longer active." });
    req.installer = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ status: false, message: "Invalid or expired token." });
  }
};

const requireLearnerAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ status: false, message: "Unauthorized" });
    }
    const decoded = jwt.verify(authHeader.split(" ")[1], process.env.JWT_SECRET);
    if (decoded.role !== "learner") {
      return res.status(403).json({ status: false, message: "Learner access required." });
    }
    const learner = await User.findOne({ _id: decoded.id, role: "learner", isActive: true }).select("_id").lean();
    if (!learner) return res.status(403).json({ status: false, message: "This learner account is no longer active." });
    req.learner = decoded;
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

const zoomMeetingSdkConfigured = Boolean(
  process.env.ZOOM_MEETING_SDK_KEY && process.env.ZOOM_MEETING_SDK_SECRET
);

// Credentials can be stored now, but outbound commands remain closed unless
// the pilot is explicitly enabled. This prevents a staging key from reaching
// a live inverter by accident.
const ashGridCredentialsPresent = Boolean(
  process.env.ASHGRIDX_API_BASE_URL && process.env.ASHGRIDX_API_KEY
);
const ashGridWebhookConfigured = Boolean(process.env.ASHGRIDX_WEBHOOK_SECRET);
const ashGridAdapterReady = process.env.ASHGRIDX_ENABLED === "true" && ashGridCredentialsPresent && ashGridWebhookConfigured;

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
        webhookConfigured: ashGridWebhookConfigured,
        mode: ashGridAdapterReady ? "sandbox" : "pilot-placeholder",
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
      { deviceNumber: String(identifier).toUpperCase() },
      { customerDeviceId: String(identifier) },
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
        { deviceNumber: search },
        { customerDeviceId: search },
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
      customerDeviceId,
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
      deviceNumber: String(reference).toUpperCase(),
      providerDeviceId: providerDeviceId || undefined,
      customerDeviceId: customerDeviceId || undefined,
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
      "customerDeviceId",
      "deviceNumber",
      "providerSiteId",
      "providerOwnerId",
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
      "lastProviderSyncAt",
      "lastCommandStatus",
      "lastCommandReference",
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

app.get("/api/admin/devices/:id/status", requireAdminAuth, async (req, res) => {
  try {
    const device = await resolveDevice(req.params.id);
    if (!device) return res.status(404).json({ status: false, message: "Device not found." });
    const [alerts, commands] = await Promise.all([
      DeviceAlert.find({ device: device._id }).sort({ occurredAt: -1 }).limit(25).lean(),
      DeviceCommand.find({ device: device._id }).sort({ createdAt: -1 }).limit(25).lean(),
    ]);
    return res.json({
      status: true,
      provider: "AshGridX",
      liveStateQuerySupported: ashGridAdapterReady,
      device,
      alerts,
      commands,
    });
  } catch (error) {
    console.error("Fetch device status error:", error);
    return res.status(500).json({ status: false, message: "Could not load device status." });
  }
});

// Admin-only test hook: it exercises the exact persistence path used by a
// signed AshGridX webhook without contacting the provider or changing a real
// inverter. This keeps the pilot fully testable before credentials arrive.
app.post("/api/admin/devices/:id/simulate-event", requireAdminAuth, async (req, res) => {
  try {
    const device = await resolveDevice(req.params.id);
    if (!device) return res.status(404).json({ status: false, message: "Device not found." });
    const event = String(req.body.event || "BYPASS").toUpperCase();
    const allowedEvents = ["BYPASS", "TAMPER_RESTORED", "DEVICE_OFFLINE", "DEVICE_ONLINE", "CONNECTED"];
    if (!allowedEvents.includes(event)) {
      return res.status(400).json({ status: false, message: `Test event must be one of: ${allowedEvents.join(", ")}.` });
    }
    const payload = {
      event,
      timestamp: String(Math.floor(Date.now() / 1000)),
      data: { deviceNumber: device.deviceNumber || device.reference, source: "BuiltRight test centre" },
    };
    const result = await processAshGridXEvent({ payload, rawBody: JSON.stringify(payload), source: "manual" });
    return res.json({ status: true, simulated: true, ...result });
  } catch (error) {
    console.error("Simulate AshGridX event error:", error);
    return res.status(500).json({ status: false, message: "Could not simulate provider event." });
  }
});

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

const numberToEnglishWords = (value) => {
  const number = Math.round(Number(value || 0));
  if (!Number.isFinite(number) || number < 0) return "Zero Naira Only";
  if (number === 0) return "Zero Naira Only";
  const ones = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"];
  const tens = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"];
  const underThousand = (n) => {
    const words = [];
    if (n >= 100) {
      words.push(`${ones[Math.floor(n / 100)]} Hundred`);
      n %= 100;
    }
    if (n >= 20) {
      words.push(tens[Math.floor(n / 10)]);
      if (n % 10) words.push(ones[n % 10]);
    } else if (n > 0) words.push(ones[n]);
    return words.join(" ");
  };
  const groups = [[1_000_000_000, "Billion"], [1_000_000, "Million"], [1_000, "Thousand"]];
  let remaining = number;
  const words = [];
  groups.forEach(([size, label]) => {
    if (remaining >= size) {
      words.push(`${underThousand(Math.floor(remaining / size))} ${label}`);
      remaining %= size;
    }
  });
  if (remaining) words.push(underThousand(remaining));
  return `${words.join(", ")} Naira Only`;
};

const buildInvoiceDocumentPdf = (projectDocument) => {
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const green = [92, 159, 147];
  const dark = [55, 58, 57];
  const border = [83, 151, 222];
  const left = 10;
  const right = 200;
  const fullWidth = right - left;
  const money = (value) => Number(value || 0).toLocaleString("en-NG", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const invoiceLabel = projectDocument.purpose === "inspection-fee" ? "INSPECTION INVOICE" : "INVOICE";
  const date = new Date(projectDocument.createdAt || Date.now());

  try { doc.addImage(builtRightEnergyLogoDataUri, "PNG", 14, 13, 48, 27); } catch (logoError) { console.error("INVOICE PDF LOGO ERROR:", logoError.message); }
  doc.setTextColor(...green);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(projectDocument.purpose === "inspection-fee" ? 21 : 27);
  doc.text(invoiceLabel, 196, 22, { align: "right" });
  doc.setFontSize(15);
  doc.text(projectDocument.reference, 196, 31, { align: "right" });
  doc.setFontSize(10);
  doc.text(`Invoice Date: ${date.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" })}`, 196, 42, { align: "right" });

  let y = 52;
  doc.setFontSize(10);
  doc.text(String(date.getFullYear()), 12, y);
  y += 10;
  const panelTop = y;
  const panelHeight = 47;
  const half = fullWidth / 2;
  doc.setFillColor(...green);
  doc.rect(left, panelTop, half, 8, "F");
  doc.rect(left + half, panelTop, half, 8, "F");
  doc.setTextColor(...dark);
  doc.setFontSize(9);
  doc.text("Bill to", left + 3, panelTop + 5.4);
  doc.text("Payment Details", left + half + 3, panelTop + 5.4);
  doc.setDrawColor(...border);
  doc.setLineWidth(0.2);
  doc.rect(left, panelTop, fullWidth, panelHeight);
  doc.line(left + half, panelTop, left + half, panelTop + panelHeight);
  const billRows = [
    ["Customer", projectDocument.customer?.fullName || "Customer"],
    ["Customer ID#", String(projectDocument.financingRequest || "").slice(-8).toUpperCase()],
    ["System Size", projectDocument.project?.systemCapacity || projectDocument.project?.systemName || "To be confirmed"],
    ["Address", projectDocument.project?.siteAddress || projectDocument.customer?.location || ""],
    ["Phone", projectDocument.customer?.phone || ""],
    ["Email", projectDocument.customer?.email || ""],
  ];
  const paymentRows = [
    ["Bank Name", inspectionPaymentDetails.bank],
    ["Account Name", inspectionPaymentDetails.accountName],
    ["Account Number", inspectionPaymentDetails.accountNumber],
  ];
  const drawDetailRows = (rows, x, valueX) => {
    let rowY = panelTop + 14;
    rows.forEach(([label, value]) => {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8.2);
      doc.text(label, x, rowY);
      doc.setFont("helvetica", "normal");
      const lines = doc.splitTextToSize(String(value || "Nil"), 48);
      doc.text(lines.slice(0, 2), valueX, rowY);
      rowY += Math.max(5.5, lines.slice(0, 2).length * 4);
    });
  };
  drawDetailRows(billRows, left + 3, left + 40);
  drawDetailRows(paymentRows, left + half + 3, left + half + 33);

  y = panelTop + panelHeight + 8;
  const columns = [11, 23, 137, 149, 173, 200];
  const drawItemHeader = () => {
    doc.setFillColor(...green);
    doc.rect(left, y, fullWidth, 8, "F");
    doc.setTextColor(...dark);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.text("S/N", 15, y + 5.4, { align: "center" });
    doc.text("Description", 80, y + 5.4, { align: "center" });
    doc.text("QTY", 143, y + 5.4, { align: "center" });
    doc.text("Unit price", 161, y + 5.4, { align: "center" });
    doc.text("Amount", 186, y + 5.4, { align: "center" });
    y += 8;
  };
  drawItemHeader();
  (projectDocument.lineItems || []).forEach((item, index) => {
    const descriptionLines = doc.splitTextToSize(String(item.description || "Item"), 108);
    const rowHeight = Math.max(8, descriptionLines.length * 4.3 + 3);
    if (y + rowHeight > 235) {
      doc.addPage();
      y = 18;
      drawItemHeader();
    }
    doc.setDrawColor(...border);
    doc.rect(left, y, fullWidth, rowHeight);
    columns.slice(1, -1).forEach((x) => doc.line(x, y, x, y + rowHeight));
    doc.setTextColor(...dark);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.2);
    doc.text(String(index + 1), 15, y + 5.3, { align: "center" });
    doc.text(descriptionLines, 25, y + 5.3);
    doc.text(String(item.quantity ?? 1), 143, y + 5.3, { align: "center" });
    doc.text(money(item.unitPrice), 171, y + 5.3, { align: "right" });
    doc.text(money(item.amount), 198, y + 5.3, { align: "right" });
    y += rowHeight;
  });

  if (y > 225) {
    doc.addPage();
    y = 25;
  } else y += 5;
  const totalsX = 104;
  const totalsWidth = 92;
  const totalRows = [
    ["SUBTOTAL", projectDocument.subtotal, true],
    ...(Number(projectDocument.discount || 0) > 0 ? [["Discount", -Number(projectDocument.discount), false]] : []),
    ...(Number(projectDocument.tax || 0) > 0 ? [["VAT / Tax", projectDocument.tax, false]] : []),
    ["GRAND TOTAL", projectDocument.total, true],
  ];
  totalRows.forEach(([label, value, emphasized]) => {
    if (emphasized) {
      doc.setFillColor(...green);
      doc.rect(totalsX, y, totalsWidth, 8, "F");
    } else {
      doc.setDrawColor(40, 40, 40);
      doc.rect(totalsX, y, totalsWidth, 8);
    }
    doc.setTextColor(...dark);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.text(label, totalsX + 3, y + 5.4);
    doc.text(money(value), totalsX + totalsWidth - 3, y + 5.4, { align: "right" });
    y += 8;
  });
  const words = numberToEnglishWords(projectDocument.total);
  const wordLines = doc.splitTextToSize(`Amount in Words: ${words}`, totalsWidth - 7);
  const wordsHeight = Math.max(14, wordLines.length * 4 + 5);
  doc.setDrawColor(40, 40, 40);
  doc.rect(totalsX, y, totalsWidth, wordsHeight);
  doc.setFont("helvetica", "bolditalic");
  doc.setFontSize(8.2);
  doc.text(wordLines, totalsX + 3, y + 5.5);
  y += wordsHeight + 4;

  doc.setTextColor(235, 65, 35);
  doc.setFont("helvetica", "bolditalic");
  doc.setFontSize(8.5);
  const validity = projectDocument.purpose === "inspection-fee"
    ? "Please note: This invoice covers the site inspection and assessment fee only."
    : "Please note: This invoice stays valid for a maximum of 2 weeks after submission.";
  doc.text(doc.splitTextToSize(validity, 120), 13, Math.min(y, 263));

  doc.setTextColor(...green);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8.5);
  doc.text("Contact for more info: 0904 999 1595 | info@builtrightltd.com | www.builtrightltd.com", 105, 282, { align: "center" });
  doc.setFont("helvetica", "bolditalic");
  doc.text("Thank you for your business!!!", 105, 287, { align: "center" });
  return Buffer.from(doc.output("arraybuffer"));
};

const buildProjectDocumentPdf = (projectDocument) => {
  if (projectDocument.type === "invoice") return buildInvoiceDocumentPdf(projectDocument);
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
  try {
    doc.addImage(builtRightEnergyLogoDataUri, "PNG", 166, 5, 27, 27);
  } catch (logoError) {
    console.error("PDF LOGO ERROR:", logoError.message);
  }
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(19);
  doc.setFont("helvetica", "bold");
  doc.text("BuiltRight Services Ltd", margin, 18);
  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.text(
    projectDocument.type === "invoice"
      ? (projectDocument.purpose === "inspection-fee" ? "SITE INSPECTION FEE INVOICE" : "PROJECT INVOICE")
      : "SOLAR PROJECT QUOTATION",
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
  doc.text(projectDocument.purpose === "inspection-fee" ? "ASSESSMENT FEE BREAKDOWN" : "PROJECT COST BREAKDOWN", margin + 3, y + 5.4);
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

const createInspectionFeeInvoice = async (loanRequest) => {
  const amount = Number(loanRequest.inspection?.feeAmount || 0);
  if (!(amount > 0)) return null;
  const reference = `BRI-${String(loanRequest.reference || loanRequest._id).replace(/[^A-Z0-9-]/gi, "").toUpperCase()}`;
  const order = await Order.findOne({ financingRequestId: loanRequest._id }).select("_id").lean();
  const payload = {
    reference,
    financingRequest: loanRequest._id,
    order: order?._id || null,
    type: "invoice",
    purpose: "inspection-fee",
    version: 1,
    status: "issued",
    title: "Site inspection, load audit and due-diligence assessment fee",
    customer: {
      fullName: loanRequest.customer?.fullName,
      email: loanRequest.customer?.email,
      phone: loanRequest.customer?.phone,
      location: loanRequest.customer?.location,
    },
    project: {
      systemName: loanRequest.items?.[0]?.name || "Solar system assessment",
      systemCapacity: loanRequest.items?.[0]?.capacity || "To be confirmed after assessment",
      siteAddress: loanRequest.customer?.location || "",
      scope: "On-site inspection, verified load audit, technical suitability checks, due diligence and installation-material assessment.",
    },
    lineItems: [{
      category: "installation-service",
      description: "Site inspection, load audit and due-diligence assessment fee",
      quantity: 1,
      unit: "service",
      unitPrice: amount,
      amount,
      source: "confirmed",
    }],
    subtotal: amount,
    total: amount,
    equityPercentage: 100,
    equityAmount: amount,
    bankFinanceAmount: 0,
    terms: `Pay to ${inspectionPaymentDetails.bank}, account ${inspectionPaymentDetails.accountNumber}, ${inspectionPaymentDetails.accountName}. Upload proof of payment in your BuiltRight customer profile for sales confirmation.`,
    notes: "This invoice covers the pre-installation site assessment only. The final system, installation materials and full project cost will be confirmed after assessment.",
    sentAt: new Date(),
    emailDelivery: { status: "not-sent" },
    createdBy: "BuiltRight sales operations",
  };
  return ProjectDocument.findOneAndUpdate(
    { financingRequest: loanRequest._id, type: "invoice", purpose: "inspection-fee" },
    { $set: payload },
    { new: true, upsert: true, setDefaultsOnInsert: true }
  );
};

const applicationEncryptionKey = () => {
  const secret = process.env.APPLICATION_DATA_ENCRYPTION_KEY || process.env.JWT_SECRET || "";
  if (!secret) throw new Error("Application-data encryption is not configured.");
  return crypto.createHash("sha256").update(secret).digest();
};

const encryptApplicationData = (data) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", applicationEncryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(data), "utf8"), cipher.final()]);
  return {
    encrypted: true,
    algorithm: "aes-256-gcm",
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
};

const decryptApplicationData = (stored) => {
  if (!stored?.encrypted) return stored || {};
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    applicationEncryptionKey(),
    Buffer.from(stored.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(stored.authTag, "base64"));
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(stored.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8"));
};

const buildRichGreenApplicationPdf = (loanRequest, quotation) => {
  const application = decryptApplicationData(loanRequest.bankApplication?.richGreenApplication?.data);
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const margin = 16;
  const width = 178;
  let y = 17;
  const ensureRoom = (height = 12) => {
    if (y + height > 280) {
      doc.addPage();
      y = 18;
    }
  };
  const text = (value) => String(value ?? "").trim() || "Not provided";
  const section = (title) => {
    ensureRoom(14);
    doc.setFillColor(21, 146, 132);
    doc.rect(margin, y, width, 8, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.text(title, margin + 3, y + 5.5);
    y += 12;
    doc.setTextColor(28, 42, 38);
  };
  const row = (label, value) => {
    const lines = doc.splitTextToSize(`${label}: ${text(value)}`, width - 4);
    ensureRoom(lines.length * 4.5 + 2);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.text(lines, margin + 2, y);
    y += lines.length * 4.5 + 1.5;
  };

  doc.setFillColor(179, 33, 39);
  doc.rect(0, 0, 210, 40, "F");
  try { doc.addImage(builtRightEnergyLogoDataUri, "PNG", 166, 5, 27, 27); } catch (logoError) { console.error("APPLICATION PDF LOGO ERROR:", logoError.message); }
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.text("BUILTRIGHT SOLAR FINANCING SCHEME", margin, 16);
  doc.setFontSize(10);
  doc.text("Powered by RichGreen Master's Investment Limited", margin, 24);
  doc.setFont("helvetica", "normal");
  doc.text("Customer Application Form", margin, 32);
  y = 49;

  section("APPLICANT INFORMATION");
  row("Full name", application.fullName);
  row("Date of birth", application.dateOfBirth);
  row("Gender", application.gender);
  row("Marital status", application.maritalStatus);
  row("Phone number", application.phoneNumber);
  row("Email address", application.emailAddress);
  row("Residential address", application.residentialAddress);
  row("State", application.state);
  row("LGA", application.lga);
  row("BVN", application.bvn);
  row("National Identification Number", application.nin);

  section("IDENTIFICATION");
  row("Type of identification", application.identificationType);
  row("ID number", application.identificationNumber);
  row("Expiry date", application.identificationExpiryDate);

  section("EMPLOYMENT OR BUSINESS DETAILS");
  row("Employment status", application.employmentStatus);
  row("Employer or business name", application.employerBusinessName);
  row("Office or business address", application.officeBusinessAddress);
  row("Position or business type", application.positionBusinessType);
  row("Monthly net income", formatDocumentMoney(application.monthlyNetIncome));
  row("Years in employment or business", application.yearsInEmploymentBusiness);

  section("BANK DETAILS");
  row("Bank name", application.bankName);
  row("Account number", application.accountNumber);
  row("Account name", application.accountName);
  row("Preferred repayment method", application.preferredRepaymentMethod);

  section("SOLAR OR INVERTER REQUIREMENT");
  row("Package selected", application.packageSelected || quotation?.project?.systemName);
  row("System capacity", application.systemCapacity || quotation?.project?.systemCapacity);
  row("Quotation amount", formatDocumentMoney(quotation?.total));
  row(`Customer equity contribution (${Number(quotation?.equityPercentage || 20)}%)`, formatDocumentMoney(quotation?.equityAmount));
  row("Finance required", formatDocumentMoney(quotation?.bankFinanceAmount));
  row("Preferred repayment tenor", `${application.preferredRepaymentTenor || ""} months`);
  row("Installation address", application.installationAddress || quotation?.project?.siteAddress);

  section("GUARANTOR DETAILS FOR BUSINESS OWNER");
  row("Guarantor name", application.guarantorName);
  row("Phone number", application.guarantorPhoneNumber);
  row("Occupation", application.guarantorOccupation);
  row("Residential address", application.guarantorResidentialAddress);
  row("Relationship to applicant", application.guarantorRelationship);

  section("CUSTOMER DECLARATION");
  row("Declaration", "The applicant confirms that the information supplied is true and complete, accepts the equity and repayment obligations in the application form, authorizes account debit and payment to BuiltRight, and acknowledges the financed-equipment ownership and default-protection terms stated in the RichGreen application.");
  row("Applicant's name", application.applicantName);
  row("Electronic signature", application.electronicSignature);
  row("Submission date", new Date(loanRequest.bankApplication?.richGreenApplication?.submittedAt || Date.now()).toLocaleDateString("en-GB"));

  section("FOR BUILTRIGHT ENERGY USE");
  row("Site inspection completed", loanRequest.assessment?.inspection?.status === "completed" ? "Yes" : "No");
  row("Load assessment completed", loanRequest.assessment?.loadAudit?.status === "completed" ? "Yes" : "No");
  row("Proforma invoice attached", quotation ? `Yes - ${quotation.reference}` : "No");
  row("Installer's name", loanRequest.installerAssignment?.installerName);

  section("FOR RICHGREEN MASTER'S INVESTMENT LIMITED USE");
  row("Application received by", "");
  row("Credit assessment", "Pending bank review");
  row("Approved amount", "");
  row("Tenor", "");
  row("Interest rate", "5% monthly reducing balance");
  row("Approval officer", "");

  ensureRoom(16);
  y += 5;
  doc.setDrawColor(21, 146, 132);
  doc.line(margin, y, margin + width, y);
  y += 6;
  doc.setTextColor(80, 91, 87);
  doc.setFontSize(7.5);
  doc.text(`BuiltRight reference: ${loanRequest.reference} | Quotation: ${quotation?.reference || "Not available"}`, margin, y);
  y += 4;
  doc.text("BuiltRight Services Ltd | 1B Adeniji Street, Off Odusami Street, Ogba, Ikeja, Lagos", margin, y);
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

app.post("/api/admin/forgot-password", async (req, res) => {
  const genericMessage = "If the email matches the BuiltRight administrator account, a secure reset link has been sent.";
  try {
    const email = String(req.body.email || "").toLowerCase().trim();
    const configuredEmail = String(process.env.ADMIN_EMAIL || "").toLowerCase().trim();
    if (email && configuredEmail && email === configuredEmail) {
      const rawToken = crypto.randomBytes(32).toString("hex");
      await AdminCredential.findOneAndUpdate(
        { email: configuredEmail },
        {
          $set: {
            passwordResetTokenHash: passwordResetTokenHash(rawToken),
            passwordResetExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
            passwordResetSentAt: new Date(),
          },
          $setOnInsert: { email: configuredEmail },
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
      const resetUrl = `${frontendUrl()}/admin/reset-password?token=${encodeURIComponent(rawToken)}`;
      await sendEmail({
        to: configuredEmail,
        subject: "Reset your BuiltRight administrator password",
        html: `<h2>BuiltRight Administration</h2><p>A password reset was requested for the BuiltRight administrator account.</p><p><a href="${resetUrl}">Set a new password</a> within one hour.</p><p>If you did not request this, you can ignore this email. Your current password remains active until the reset is completed.</p>`,
      });
    }
    return res.json({ status: true, message: genericMessage });
  } catch (error) {
    console.error("ADMIN FORGOT PASSWORD ERROR:", error.message);
    return res.json({ status: true, message: genericMessage });
  }
});

app.post("/api/admin/reset-password", async (req, res) => {
  try {
    const rawToken = String(req.body.token || "").trim();
    const password = String(req.body.password || "");
    if (!/^[a-f0-9]{64}$/.test(rawToken) || password.length < 12) {
      return res.status(400).json({ status: false, message: "Use a valid reset link and a password of at least 12 characters." });
    }
    const credential = await AdminCredential.findOne({
      passwordResetTokenHash: passwordResetTokenHash(rawToken),
      passwordResetExpiresAt: { $gt: new Date() },
    });
    if (!credential) return res.status(400).json({ status: false, message: "This password reset link is invalid or expired." });
    credential.passwordHash = await bcrypt.hash(password, 12);
    credential.passwordResetTokenHash = "";
    credential.passwordResetExpiresAt = null;
    await credential.save();
    return res.json({ status: true, message: "Administrator password updated. You can now sign in." });
  } catch (error) {
    console.error("ADMIN RESET PASSWORD ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not reset the administrator password." });
  }
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail = String(email || "").toLowerCase().trim();
    const configuredEmail = String(process.env.ADMIN_EMAIL || "").toLowerCase().trim();
    const credential = normalizedEmail === configuredEmail
      ? await AdminCredential.findOne({ email: configuredEmail })
      : null;
    const passwordMatches = credential?.passwordHash
      ? await bcrypt.compare(String(password || ""), credential.passwordHash)
      : String(password || "") === String(process.env.ADMIN_PASSWORD || "");

    if (normalizedEmail !== configuredEmail || !passwordMatches) {
      return res.status(401).json({
        status: false,
        message: "Invalid admin credentials.",
      });
    }

    const token = createToken({
      email: normalizedEmail,
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

app.post("/api/auth/forgot-password", async (req, res) => {
  const genericMessage = "If an active account matches those details, a secure reset link has been sent.";
  try {
    const email = String(req.body.email || "").toLowerCase().trim();
    const requestedRole = String(req.body.role || "").toLowerCase().trim();
    const allowedRoles = Object.keys(passwordResetLoginPaths);
    const query = { email, isActive: true };
    if (allowedRoles.includes(requestedRole)) query.role = requestedRole;
    const user = email ? await User.findOne(query) : null;
    if (user && allowedRoles.includes(user.role)) {
      const rawToken = crypto.randomBytes(32).toString("hex");
      user.passwordResetTokenHash = passwordResetTokenHash(rawToken);
      user.passwordResetExpiresAt = new Date(Date.now() + 60 * 60 * 1000);
      user.passwordResetSentAt = new Date();
      await user.save();
      const resetUrl = `${frontendUrl()}/reset-password?token=${encodeURIComponent(rawToken)}`;
      await sendEmail({
        to: user.email,
        subject: "Reset your BuiltRight password",
        html: `<h2>BuiltRight Password Reset</h2><p>Hello ${safeHtml(user.fullName)},</p><p>A password reset was requested for your BuiltRight ${passwordResetRoleLabels[user.role]} account.</p><p><a href="${resetUrl}">Set a new password</a> within one hour.</p><p>If you did not request this, you can ignore this email. Your current password remains active until the reset is completed.</p>`,
      });
    }
    return res.json({ status: true, message: genericMessage });
  } catch (error) {
    console.error("FORGOT PASSWORD ERROR:", error.message);
    return res.json({ status: true, message: genericMessage });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const rawToken = String(req.body.token || "").trim();
    const password = String(req.body.password || "");
    if (!/^[a-f0-9]{64}$/.test(rawToken)) {
      return res.status(400).json({ status: false, message: "This password reset link is invalid or expired." });
    }
    const user = await User.findOne({
      isActive: true,
      passwordResetTokenHash: passwordResetTokenHash(rawToken),
      passwordResetExpiresAt: { $gt: new Date() },
    });
    if (!user) return res.status(400).json({ status: false, message: "This password reset link is invalid or expired." });
    const minimumLength = user.role === "accountant" ? 12 : 8;
    if (password.length < minimumLength) {
      return res.status(400).json({ status: false, message: `Use a password of at least ${minimumLength} characters.` });
    }
    user.password = await bcrypt.hash(password, 12);
    user.passwordResetTokenHash = "";
    user.passwordResetExpiresAt = null;
    await user.save();
    return res.json({
      status: true,
      message: "Password updated. You can now sign in.",
      loginPath: passwordResetLoginPaths[user.role] || "/auth",
    });
  } catch (error) {
    console.error("RESET PASSWORD ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not reset the password." });
  }
});

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
  const emailResult = sendEmail({
    to: installer.email,
    subject: `${reassigned ? "Reassigned" : "New"} inspection assignment - ${loanRequest.reference}`,
    html: `<h2>${reassigned ? "Inspection reassigned" : "New inspection assignment"}</h2><p>Hello ${safeHtml(installer.fullName)},</p><p>You have been assigned to ${safeHtml(loanRequest.customer.fullName)}'s solar-financing project.</p><ul><li><strong>Reference:</strong> ${safeHtml(loanRequest.reference)}</li><li><strong>Customer phone:</strong> ${safeHtml(loanRequest.customer.phone)}</li><li><strong>Project location:</strong> ${safeHtml(loanRequest.customer.location || "To be confirmed")}</li></ul><p>Please sign in, accept or decline the assignment, and arrange a convenient inspection time with the customer.</p><p><a href="${profileUrl}">Open installer profile</a></p>`,
  });
  const smsResult = installer.phone
    ? sendSms({
      to: installer.phone,
      message: `BuiltRight: ${reassigned ? "Reassigned" : "New"} inspection ${loanRequest.reference} for ${loanRequest.customer.fullName}, ${loanRequest.customer.phone}, ${loanRequest.customer.location || "location pending"}. Log in: ${profileUrl}`,
    })
    : Promise.resolve({ status: "missing-phone" });
  const [emailOutcome, smsOutcome] = await Promise.allSettled([emailResult, smsResult]);
  if (smsOutcome.status === "rejected") console.error("INSTALLER ASSIGNMENT SMS ERROR:", smsOutcome.reason?.message || smsOutcome.reason);
  if (emailOutcome.status === "rejected") throw emailOutcome.reason;
};

const sanitizeInstallerAssignment = (loanRequest) => {
  const value = loanRequest?.toObject ? loanRequest.toObject() : { ...loanRequest };
  return {
    ...value,
    inspection: value.inspection ? { ...value.inspection, feeAmount: undefined, paymentProof: undefined } : value.inspection,
  };
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

const assignSpecificInstallerToLoanRequest = async (loanRequest, installerId, assignedBy = "BuiltRight sales") => {
  const installer = await User.findOne({
    _id: installerId,
    role: "installer",
    isActive: true,
    "installerProfile.availability": "available",
  });
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
    reassignmentCount: Number(loanRequest.installerAssignment?.reassignmentCount || 0),
    history: [...previousHistory, {
      installer: installer._id,
      installerName: installer.fullName,
      status: "assigned",
      note: `Manually assigned by ${assignedBy}.`,
      changedAt: new Date(),
    }],
  };
  loanRequest.status = "internal-review";
  loanRequest.statusHistory.push({
    status: "internal-review",
    source: "sales",
    note: `Site assessment assigned to ${installer.fullName} by ${assignedBy}.`,
  });
  return installer;
};

const sendSubmissionConfirmationEmail = async (loanRequest, order = null) => {
  const installerName = loanRequest.installerAssignment?.installerName || "a BuiltRight installer";
  const isOutright = loanRequest.paymentMethod === "outright";
  const salesAssisted = ["sales-whatsapp", "sales-assisted"].includes(loanRequest.intake?.source);
  const completedOffline = loanRequest.inspection?.status === "completed" && !loanRequest.installerAssignment?.installer;
  const assessmentMessage = completedOffline
    ? "Your completed offline inspection, load audit, and assessment payment have been recorded. BuiltRight will now verify the assessment details and continue the due-diligence and quotation process."
    : `${safeHtml(installerName)} has been assigned and will contact you shortly to arrange a convenient time for your site inspection.`;
  const orderMessage = order?.orderNumber
    ? `<p>Your project order <strong>${safeHtml(order.orderNumber)}</strong> has been opened and is currently being processed. The amount will be updated after the final project quotation is approved.</p>`
    : "";
  await sendEmail({
    to: loanRequest.customer.email,
    subject: `BuiltRight ${isOutright ? "outright-purchase" : "financing"} request received - ${loanRequest.reference}`,
    html: `<h2>Your ${isOutright ? "outright-purchase" : "financing"} request was submitted successfully</h2><p>Hello ${safeHtml(loanRequest.customer.fullName)},</p><p>We have received your request ${safeHtml(loanRequest.reference)}. ${assessmentMessage}</p>${orderMessage}<p>After the required assessment and due diligence, BuiltRight will prepare your final project quotation for approval.${isOutright ? " Once approved, you will receive a BuiltRight invoice for the full confirmed project cost." : ""}</p>${salesAssisted ? `<p><a href="${frontendUrl()}/auth">Create or sign in to your BuiltRight customer profile</a> using this email address to view project updates and documents.</p>` : ""}`,
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

app.get("/api/loan-requests", requireOperationsAuth, async (req, res) => {
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
    const loanRequest = await LoanRequest.findById(req.params.id).lean();

    if (!loanRequest) {
      return res.status(404).json({
        status: false,
        message: "Loan request not found.",
      });
    }

    const linkedDevices = await Device.find({ financingRequest: loanRequest._id }).select("_id").lean();
    const deviceIds = linkedDevices.map((device) => device._id);
    await Promise.all([
      ProjectDocument.deleteMany({ financingRequest: loanRequest._id }),
      Order.deleteMany({ financingRequestId: loanRequest._id }),
      DeviceCommand.deleteMany({ device: { $in: deviceIds } }),
      DeviceAlert.deleteMany({ device: { $in: deviceIds } }),
      Device.deleteMany({ _id: { $in: deviceIds } }),
      LoanRequest.deleteOne({ _id: loanRequest._id }),
    ]);

    return res.json({
      status: true,
      message: "Project and all linked quotations, invoices, orders, devices, alerts, and commands were permanently deleted.",
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

app.get("/api/loan-requests/:id/workspace", requireOperationsAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findById(req.params.id).lean();
    if (!loanRequest) {
      return res.status(404).json({ status: false, message: "Financing case not found." });
    }

    const [documents, order] = await Promise.all([
      ProjectDocument.find({ financingRequest: loanRequest._id }).sort({ createdAt: -1 }).lean(),
      Order.findOne({ financingRequestId: loanRequest._id }).lean(),
    ]);
    return res.json({ status: true, loanRequest, documents, order });
  } catch (error) {
    console.error("LOAD FINANCING WORKSPACE ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load the financing workspace." });
  }
});

/* =========================
   SALES OPERATIONS
========================= */

app.post("/api/sales/activate", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password || password.length < 8) {
      return res.status(400).json({ status: false, message: "A valid invitation token and an 8-character password are required." });
    }
    const user = await User.findOne({
      role: "sales",
      "salesProfile.invitationToken": token,
      "salesProfile.invitationExpiresAt": { $gt: new Date() },
    });
    if (!user) return res.status(400).json({ status: false, message: "This sales invitation is invalid or has expired." });
    user.password = await bcrypt.hash(password, 10);
    user.isActive = true;
    user.salesProfile.invitationToken = "";
    user.salesProfile.invitationExpiresAt = null;
    user.salesProfile.activatedAt = new Date();
    await user.save();
    return res.json({ status: true, message: "Sales account activated. You can now sign in." });
  } catch (error) {
    console.error("SALES ACTIVATION ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Sales account could not be activated." });
  }
});

app.post("/api/sales/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").toLowerCase().trim();
    const user = await User.findOne({ email, role: "sales" });
    if (!user || !user.isActive || !(await bcrypt.compare(req.body.password || "", user.password))) {
      return res.status(401).json({ status: false, message: "Invalid sales credentials." });
    }
    const token = createToken({ id: user._id, email: user.email, role: "sales", fullName: user.fullName });
    return res.json({ status: true, token, user: { id: user._id, fullName: user.fullName, email: user.email, role: user.role } });
  } catch (error) {
    console.error("SALES LOGIN ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Sales login failed." });
  }
});

app.get("/api/sales/installers", requireOperationsAuth, async (req, res) => {
  try {
    const installers = await User.find({
      role: "installer",
      isActive: true,
      "installerProfile.availability": "available",
    }).select("fullName email installerProfile.availability").sort({ fullName: 1 }).lean();
    return res.json({ status: true, installers });
  } catch (error) {
    console.error("SALES INSTALLER LIST ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load available installers." });
  }
});

app.get("/api/sales/projects", requireOperationsAuth, async (req, res) => {
  try {
    const projects = await LoanRequest.find({ "testRun.isTest": { $ne: true } })
      .sort({ createdAt: -1 })
      .lean();
    const projectIds = projects.map((project) => project._id);
    const [orders, invoices] = await Promise.all([
      Order.find({ financingRequestId: { $in: projectIds } }).lean(),
      ProjectDocument.find({ financingRequest: { $in: projectIds }, type: "invoice" })
        .sort({ createdAt: -1 })
        .lean(),
    ]);
    const ordersByProject = new Map(orders.map((order) => [String(order.financingRequestId), order]));
    const invoicesByProject = new Map();
    const inspectionInvoicesByProject = new Map();
    invoices.forEach((invoice) => {
      const key = String(invoice.financingRequest);
      if (invoice.purpose === "inspection-fee") {
        if (!inspectionInvoicesByProject.has(key)) inspectionInvoicesByProject.set(key, invoice);
      } else if (!invoicesByProject.has(key)) {
        invoicesByProject.set(key, invoice);
      }
    });
    const customers = projects.map((project) => {
      const richGreenApplication = project.bankApplication?.richGreenApplication;
      return {
        ...project,
        bankApplication: {
          ...project.bankApplication,
          richGreenApplication: richGreenApplication ? {
            status: richGreenApplication.status,
            submittedAt: richGreenApplication.submittedAt,
            submittedBy: richGreenApplication.submittedBy,
            quotationDocument: richGreenApplication.quotationDocument,
          } : null,
        },
        order: ordersByProject.get(String(project._id)) || null,
        invoice: invoicesByProject.get(String(project._id)) || null,
        inspectionInvoice: inspectionInvoicesByProject.get(String(project._id)) || null,
      };
    });
    return res.json({ status: true, customers });
  } catch (error) {
    console.error("SALES CUSTOMER LIST ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load registered customers." });
  }
});

app.post("/api/sales/projects", requireOperationsAuth, async (req, res) => {
  try {
    const { customer = {}, installerId, inspectionFeeAmount, paymentMethod, financeInstitution, systemDescription, notes, consentCaptured, inspectionCompleted } = req.body;
    if (!customer.fullName || !customer.email || !customer.phone || !customer.location) {
      return res.status(400).json({ status: false, message: "Customer name, email, phone number, and project location are required." });
    }
    if (!consentCaptured) {
      return res.status(400).json({ status: false, message: "Confirm that the customer consented to BuiltRight recording and using the supplied project information." });
    }
    const completedOffline = Boolean(inspectionCompleted);
    if (!completedOffline && !installerId) return res.status(400).json({ status: false, message: "Select the installer who will perform the site assessment." });
    const normalizedFee = Number(String(inspectionFeeAmount ?? "").replace(/[^\d.]/g, ""));
    if (!completedOffline && !(normalizedFee > 0)) return res.status(400).json({ status: false, message: "Enter an assessment fee greater than zero." });
    const selectedPaymentMethod = paymentMethod === "outright" ? "outright" : "bank-financing";
    const selectedFinanceInstitution = selectedPaymentMethod === "outright" ? "Not applicable — outright payment" : (financeInstitution || "Bank partner pending");
    const equityPercentage = selectedPaymentMethod === "outright" ? 100 : (selectedFinanceInstitution === "LOTUS Bank" ? 10 : 20);
    const salesUser = await User.findById(req.staff.id).select("fullName email").lean();
    const salesName = salesUser?.fullName || req.staff.fullName || req.staff.email;
    const loanRequest = await LoanRequest.create({
      customer: {
        fullName: String(customer.fullName).trim(),
        email: String(customer.email).toLowerCase().trim(),
        phone: String(customer.phone).trim(),
        location: String(customer.location).trim(),
      },
      intake: { source: "sales-assisted", createdBy: req.staff.id, createdByName: salesName, createdByEmail: req.staff.email, capturedAt: new Date() },
      productSource: "BuiltRight Marketplace",
      paymentMethod: selectedPaymentMethod,
      installationProvider: "BuiltRight Services Ltd",
      financeInstitution: selectedFinanceInstitution,
      items: [{ id: `sales-${Date.now()}`, name: String(systemDescription || "System to be finalized after site assessment"), quantity: 1, price: null, category: "solar-system", type: "Sales-assisted enquiry", capacity: "" }],
      consentToShare: true,
      preferredContact: "WhatsApp",
      bankApplication: { provider: selectedFinanceInstitution, status: selectedPaymentMethod === "outright" ? "not-required" : "not-started" },
      deposit: { percentage: equityPercentage, status: "not-due" },
      assessment: {
        status: completedOffline ? "in-progress" : "open",
        triggeredAt: new Date(),
        inspection: completedOffline
          ? { status: "completed", result: "pass", completedAt: new Date(), completedBy: salesName, notes: "Site inspection was completed and confirmed through the offline/WhatsApp sales process." }
          : { status: "pending", result: "pending" },
        loadAudit: {
          status: completedOffline ? "completed" : "pending",
          result: completedOffline ? "pass" : "pending",
          completedAt: completedOffline ? new Date() : null,
          completedBy: completedOffline ? salesName : "",
          notes: completedOffline
            ? "Customer load audit was completed through the offline/WhatsApp sales process. Sales must record the verified sizing details before preparing the final quotation."
            : "Projected load discussion completed by sales on WhatsApp. Installer will record the verified on-site load audit.",
        },
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
      inspection: completedOffline
        ? { feeAmount: normalizedFee > 0 ? normalizedFee : null, feeStatus: "payment-confirmed", status: "completed", completedAt: new Date(), paymentConfirmedAt: new Date() }
        : { feeAmount: normalizedFee, feeStatus: "not-requested", status: "not-scheduled" },
      status: completedOffline ? "inspection-completed" : "submitted",
      statusHistory: [{
        status: completedOffline ? "inspection-completed" : "submitted",
        source: "sales",
        note: completedOffline
          ? `Customer registered by ${salesName}; offline/WhatsApp inspection, load audit, and assessment payment recorded as completed.`
          : `Customer assessment booking created by ${salesName}; assessment fee recorded by sales.`,
      }],
      notes: String(notes || ""),
    });
    let installer = null;
    if (!completedOffline) {
      installer = await assignSpecificInstallerToLoanRequest(loanRequest, installerId, salesName);
      if (!installer) {
        await LoanRequest.deleteOne({ _id: loanRequest._id });
        return res.status(409).json({ status: false, message: "The selected installer is no longer available. Refresh and choose another installer." });
      }
    }
    await loanRequest.save();
    let order;
    try {
      order = await Order.create({
        orderNumber: generateOrderNumber(),
        reference: `FIN-${loanRequest.reference}`,
        source: selectedPaymentMethod === "outright" ? "Manual" : "Financing",
        customer: {
          fullName: loanRequest.customer.fullName,
          email: loanRequest.customer.email,
          phone: loanRequest.customer.phone,
        },
        items: loanRequest.items,
        amount: null,
        date: new Date().toLocaleDateString("en-NG"),
        status: "Processing",
        financingRequestId: loanRequest._id,
      });
    } catch (orderError) {
      await LoanRequest.deleteOne({ _id: loanRequest._id });
      throw orderError;
    }
    if (installer) {
      try { await sendInstallerAssignmentEmail(loanRequest, installer); } catch (mailError) { console.error("SALES ASSIGNMENT EMAIL ERROR:", mailError.message); }
    }
    try { await sendSubmissionConfirmationEmail(loanRequest, order); } catch (mailError) { console.error("SALES CUSTOMER CONFIRMATION ERROR:", mailError.message); }
    return res.status(201).json({
      status: true,
      message: completedOffline
        ? `Customer registered, offline assessment recorded, and order ${order.orderNumber} created.`
        : `Customer registered, order ${order.orderNumber} created, and site assessment assigned to ${installer.fullName}.`,
      loanRequest,
      order,
    });
  } catch (error) {
    console.error("CREATE SALES PROJECT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not register the customer project." });
  }
});

app.patch("/api/sales/projects/:id/assessment-fee", requireOperationsAuth, async (req, res) => {
  try {
    const normalizedFee = Number(String(req.body.inspectionFeeAmount ?? "").replace(/[^\d.]/g, ""));
    if (!(normalizedFee > 0)) return res.status(400).json({ status: false, message: "Enter an assessment fee greater than zero." });
    const loanRequest = await LoanRequest.findById(req.params.id);
    if (!loanRequest) return res.status(404).json({ status: false, message: "Customer project not found." });
    if (["payment-requested", "proof-submitted", "payment-confirmed"].includes(loanRequest.inspection?.feeStatus)) {
      return res.status(409).json({ status: false, message: "The assessment fee can no longer be changed because payment processing has started." });
    }
    loanRequest.inspection.feeAmount = normalizedFee;
    loanRequest.statusHistory.push({ status: loanRequest.status, source: "sales", note: "Assessment fee updated by the sales team." });
    await loanRequest.save();
    return res.json({ status: true, message: "Assessment fee updated.", loanRequest });
  } catch (error) {
    console.error("UPDATE ASSESSMENT FEE ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not update the assessment fee." });
  }
});

app.patch("/api/sales/projects/:id/assessment-payment-confirmed", requireOperationsAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findById(req.params.id);
    if (!loanRequest) return res.status(404).json({ status: false, message: "Customer project not found." });
    if (loanRequest.inspection?.feeStatus !== "proof-submitted" || !loanRequest.inspection?.paymentProof?.url) {
      return res.status(409).json({ status: false, message: "The customer must upload payment proof before sales can confirm receipt." });
    }
    loanRequest.inspection.feeStatus = "payment-confirmed";
    loanRequest.inspection.paymentConfirmedAt = new Date();
    loanRequest.inspection.status = "in-progress";
    loanRequest.installerAssignment.status = "accepted";
    loanRequest.assessment.status = "in-progress";
    loanRequest.statusHistory.push({ status: loanRequest.status, source: "sales", note: "Assessment payment confirmed by the sales team; installer cleared to proceed." });
    await loanRequest.save();
    const installer = await User.findById(loanRequest.installerAssignment?.installer).select("fullName email phone").lean();
    if (installer) {
      const portalUrl = `${frontendUrl()}/installer/assignments`;
      const outcomes = await Promise.allSettled([
        sendEmail({
          to: installer.email,
          subject: `Assessment cleared to proceed - ${loanRequest.reference}`,
          html: `<p>Hello ${safeHtml(installer.fullName)},</p><p>Sales has confirmed the customer's assessment payment for ${safeHtml(loanRequest.reference)}. You may now proceed with the scheduled visit and complete the field report.</p><p><a href="${portalUrl}">Open installer profile</a></p>`,
        }),
        installer.phone ? sendSms({ to: installer.phone, message: `BuiltRight: Assessment ${loanRequest.reference} is cleared to proceed. Open your installer profile: ${portalUrl}` }) : Promise.resolve(),
      ]);
      outcomes.filter((item) => item.status === "rejected").forEach((item) => console.error("ASSESSMENT CLEARANCE NOTICE ERROR:", item.reason?.message || item.reason));
    }
    return res.json({ status: true, message: "Assessment payment confirmed. The installer has been cleared to proceed.", loanRequest });
  } catch (error) {
    console.error("CONFIRM ASSESSMENT PAYMENT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not confirm the assessment payment." });
  }
});

app.patch("/api/sales/projects/:id/installer", requireOperationsAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findById(req.params.id);
    if (!loanRequest) return res.status(404).json({ status: false, message: "Customer project not found." });
    if (["completed"].includes(loanRequest.installerAssignment?.status)) {
      return res.status(409).json({ status: false, message: "A completed site assessment cannot be reassigned." });
    }
    const salesUser = await User.findById(req.staff.id).select("fullName").lean();
    const installer = await assignSpecificInstallerToLoanRequest(loanRequest, req.body.installerId, salesUser?.fullName || req.staff.email);
    if (!installer) return res.status(409).json({ status: false, message: "The selected installer is not available." });
    await loanRequest.save();
    try { await sendInstallerAssignmentEmail(loanRequest, installer, true); } catch (mailError) { console.error("MANUAL ASSIGNMENT EMAIL ERROR:", mailError.message); }
    return res.json({ status: true, message: `Project assigned to ${installer.fullName}.`, loanRequest });
  } catch (error) {
    console.error("MANUAL SALES ASSIGNMENT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not assign the installer." });
  }
});

app.get("/api/sales/projects/:id/richgreen-application/download", requireOperationsAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findById(req.params.id);
    if (!loanRequest) return res.status(404).json({ status: false, message: "Customer project not found." });
    if (loanRequest.bankApplication?.richGreenApplication?.status !== "submitted") {
      return res.status(409).json({ status: false, message: "The customer has not submitted the RichGreen application." });
    }
    const quotation = await ProjectDocument.findOne({ financingRequest: loanRequest._id, type: "quotation", status: "approved" }).sort({ version: -1 });
    if (!quotation) return res.status(409).json({ status: false, message: "The approved quotation is not available." });
    const pdf = buildRichGreenApplicationPdf(loanRequest, quotation);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="RichGreen-Application-${loanRequest.reference}.pdf"`);
    res.setHeader("Cache-Control", "no-store");
    return res.send(pdf);
  } catch (error) {
    console.error("DOWNLOAD RICHGREEN APPLICATION ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not download the RichGreen application." });
  }
});

/* =========================
   INSTALLER AUTH
========================= */

/* =========================
   LEARNER AUTH
========================= */

app.post("/api/learner/activate", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password || password.length < 8) {
      return res.status(400).json({ status: false, message: "A valid invitation token and an 8-character password are required." });
    }
    const learner = await User.findOne({
      role: "learner",
      "learnerProfile.invitationToken": token,
      "learnerProfile.invitationExpiresAt": { $gt: new Date() },
    });
    if (!learner) {
      return res.status(400).json({ status: false, message: "This learner invitation is invalid or has expired." });
    }
    learner.password = await bcrypt.hash(password, 10);
    learner.isActive = true;
    learner.learnerProfile.invitationToken = "";
    learner.learnerProfile.invitationExpiresAt = null;
    learner.learnerProfile.activatedAt = new Date();
    learner.learnerProfile.enrollmentStatus = "active";
    await learner.save();
    return res.json({ status: true, message: "Learner account activated. You can now sign in." });
  } catch (error) {
    console.error("LEARNER ACTIVATION ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Learner account could not be activated." });
  }
});

app.post("/api/learner/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const learner = await User.findOne({ email: String(email || "").toLowerCase(), role: "learner" });
    if (!learner || !learner.isActive || !(await bcrypt.compare(password || "", learner.password))) {
      return res.status(401).json({ status: false, message: "Invalid learner credentials." });
    }
    const token = createToken({ id: learner._id, email: learner.email, role: "learner" });
    return res.json({
      status: true,
      token,
      user: { id: learner._id, fullName: learner.fullName, email: learner.email, phone: learner.phone, role: learner.role },
    });
  } catch (error) {
    console.error("LEARNER LOGIN ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Learner login failed." });
  }
});

app.get("/api/learner/portal", requireLearnerAuth, async (req, res) => {
  try {
    const learner = await User.findOne({ _id: req.learner.id, role: "learner" })
      .select("fullName email phone learnerProfile")
      .lean();
    if (!learner || learner.learnerProfile?.enrollmentStatus === "suspended") {
      return res.status(403).json({ status: false, message: "This learner enrolment is not active." });
    }
    const profile = learner.learnerProfile || {};
    const settings = await TrainingSettings.findOne().lean();
    return res.json({
      status: true,
      learner: {
        id: learner._id,
        fullName: learner.fullName,
        email: learner.email,
        phone: learner.phone,
        enrollmentStatus: profile.enrollmentStatus || "active",
      },
      cohort: {
        name: settings?.cohortName || profile.cohortName || "BuiltRight Solar Installation Training",
        startDate: profile.cohortStart || null,
        endDate: profile.cohortEnd || null,
        schedule: "Monday–Friday · 10:00–16:00 WAT",
        liveUrl: settings?.liveClassUrl || process.env.TRAINING_LIVE_CLASS_URL || "",
        meetingSdkReady: Boolean(zoomMeetingSdkConfigured && settings?.meetingNumber),
        liveSessionActive: Boolean(settings?.liveSessionActive),
        brochureUrl: settings?.brochureUrl || process.env.TRAINING_BROCHURE_URL || "",
        curriculum: [
          { week: "Week 1", title: "Solar and electrical foundations", topics: ["Solar fundamentals", "Electrical safety", "System sizing and components"] },
          { week: "Week 2", title: "Installation practice", topics: ["Mounting and wiring", "Inverter and battery setup", "Protection and changeover systems"] },
          { week: "Week 3", title: "Testing and commissioning", topics: ["Load audit", "Testing and fault finding", "Commissioning documentation"] },
          { week: "Week 4", title: "Maintenance and field delivery", topics: ["Preventive maintenance", "Customer handover", "Business and project best practice"] },
        ],
      },
    });
  } catch (error) {
    console.error("LEARNER PORTAL ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load the training portal." });
  }
});

app.post("/api/learner/zoom-signature", requireLearnerAuth, async (req, res) => {
  try {
    const learner = await User.findOne({ _id: req.learner.id, role: "learner", isActive: true })
      .select("fullName email learnerProfile")
      .lean();
    if (!learner || learner.learnerProfile?.enrollmentStatus === "suspended") {
      return res.status(403).json({ status: false, message: "This learner enrolment is not active." });
    }

    const settings = await TrainingSettings.findOne().lean();
    if (!settings?.liveSessionActive) {
      return res.status(403).json({ status: false, message: "The live classroom is not open yet." });
    }
    if (!zoomMeetingSdkConfigured) {
      return res.status(503).json({ status: false, message: "The Zoom classroom has not been connected yet." });
    }

    const meetingNumber = String(settings.meetingNumber || "").replace(/\D/g, "");
    if (!meetingNumber) {
      return res.status(503).json({ status: false, message: "No Zoom meeting has been assigned to this cohort." });
    }

    const issuedAt = Math.floor(Date.now() / 1000) - 30;
    const expiresAt = issuedAt + 2 * 60 * 60;
    const sdkKey = process.env.ZOOM_MEETING_SDK_KEY;
    const signature = jwt.sign(
      {
        sdkKey,
        appKey: sdkKey,
        mn: meetingNumber,
        role: 0,
        iat: issuedAt,
        exp: expiresAt,
        tokenExp: expiresAt,
      },
      process.env.ZOOM_MEETING_SDK_SECRET,
      { algorithm: "HS256", header: { typ: "JWT" } }
    );

    return res.json({
      status: true,
      sdkKey,
      signature,
      meetingNumber,
      passcode: settings.meetingPasscode || "",
      userName: learner.fullName,
      userEmail: learner.email,
    });
  } catch (error) {
    console.error("ZOOM SIGNATURE ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not open the Zoom classroom." });
  }
});

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
    return res.json({ status: true, assignments: assignments.map(sanitizeInstallerAssignment) });
  } catch (error) {
    console.error("INSTALLER ASSIGNMENTS ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load installer assignments." });
  }
});

app.patch("/api/installer/assignments/:id/accept", requireInstallerAuth, async (req, res) => {
  try {
    const { scheduledAt } = req.body;
    const normalizedScheduledAt = String(scheduledAt || "").trim();
    const loanRequest = await LoanRequest.findOne({ _id: req.params.id, "installerAssignment.installer": req.installer.id });
    if (!loanRequest || !["assigned", "accepted"].includes(loanRequest.installerAssignment?.status)) {
      return res.status(404).json({ status: false, message: "This assignment is no longer available for acceptance." });
    }
    if (!normalizedScheduledAt) {
      loanRequest.installerAssignment.status = "accepted";
      loanRequest.installerAssignment.acceptedAt ||= new Date();
      loanRequest.installerAssignment.history.push({ installer: req.installer.id, installerName: loanRequest.installerAssignment.installerName, status: "accepted", note: "Installer accepted the assignment and will contact the customer before scheduling.", changedAt: new Date() });
      await loanRequest.save();
      return res.json({ status: true, message: "Assignment accepted. Contact the customer, then set the agreed inspection date and time.", loanRequest: sanitizeInstallerAssignment(loanRequest) });
    }
    const normalizedFee = Number(loanRequest.inspection?.feeAmount);
    const normalizedLocation = String(loanRequest.customer?.location || "").trim();
    if (!(normalizedFee > 0)) return res.status(409).json({ status: false, message: "The assessment fee has not been set by sales. Ask the sales team to update this project before scheduling." });
    const scheduledDate = new Date(normalizedScheduledAt);
    if (Number.isNaN(scheduledDate.getTime()) || scheduledDate <= new Date()) {
      return res.status(400).json({ status: false, message: "Choose a future inspection date and time." });
    }
    loanRequest.installerAssignment.status = "scheduled";
    loanRequest.installerAssignment.acceptedAt = new Date();
    loanRequest.installerAssignment.history.push({ installer: req.installer.id, installerName: loanRequest.installerAssignment.installerName, status: "accepted", note: "Installer accepted and scheduled the inspection.", changedAt: new Date() });
    loanRequest.inspection.status = "scheduled";
    loanRequest.inspection.scheduledAt = scheduledDate;
    loanRequest.inspection.assignee = loanRequest.installerAssignment.installerName;
    loanRequest.inspection.notes = `Inspection location: ${normalizedLocation}`;
    loanRequest.inspection.feeStatus = "payment-requested";
    loanRequest.assessment.inspection.status = "scheduled";
    loanRequest.assessment.status = "in-progress";
    loanRequest.status = "inspection-scheduled";
    loanRequest.statusHistory.push({ status: "inspection-scheduled", source: "installer", note: `Inspection scheduled by ${loanRequest.installerAssignment.installerName}.` });
    await loanRequest.save();
    let inspectionInvoice = null;
    try {
      inspectionInvoice = await createInspectionFeeInvoice(loanRequest);
    } catch (invoiceError) {
      console.error("INSPECTION INVOICE ERROR:", invoiceError.message);
    }
    try {
      const attachments = inspectionInvoice ? [{
        filename: `BuiltRight-Inspection-Invoice-${inspectionInvoice.reference}.pdf`,
        content: buildProjectDocumentPdf(inspectionInvoice),
        contentType: "application/pdf",
      }] : [];
      await sendEmail({
        to: loanRequest.customer.email,
        subject: `BuiltRight inspection scheduled - ${loanRequest.reference}`,
        html: `<h2>Your site inspection is scheduled</h2><p>Hello ${safeHtml(loanRequest.customer.fullName)},</p><p>${safeHtml(loanRequest.installerAssignment.installerName)} has scheduled your site inspection.</p><ul><li><strong>Date and time:</strong> ${safeHtml(scheduledDate.toLocaleString("en-NG", { dateStyle: "full", timeStyle: "short" }))}</li><li><strong>Location:</strong> ${safeHtml(normalizedLocation)}</li><li><strong>Inspection fee:</strong> ${formatNaira(normalizedFee)}</li></ul><p>Your branded inspection-fee invoice is attached and is also available in your BuiltRight customer profile.</p><p>Please make the inspection-fee payment using the details below. Then sign in to your BuiltRight customer profile, upload your payment proof, and click <strong>I have paid — submit proof</strong>. Your installer can begin the inspection only after sales confirms receipt.</p><ul><li><strong>Bank:</strong> ${safeHtml(inspectionPaymentDetails.bank)}</li><li><strong>Account number:</strong> ${safeHtml(inspectionPaymentDetails.accountNumber)}</li><li><strong>Account name:</strong> ${safeHtml(inspectionPaymentDetails.accountName)}</li></ul><p><a href="${frontendUrl()}/customer/financing">Open customer profile</a></p>`,
        attachments,
      });
      if (inspectionInvoice) {
        inspectionInvoice.emailDelivery = { status: "sent", sentAt: new Date(), error: "" };
        await inspectionInvoice.save();
      }
    } catch (mailError) {
      console.error("INSPECTION SCHEDULE EMAIL ERROR:", mailError.message);
      if (inspectionInvoice) {
        inspectionInvoice.emailDelivery = { status: "failed", sentAt: null, error: mailError.message };
        await inspectionInvoice.save();
      }
    }
    try {
      await sendSms({
        to: loanRequest.customer.phone,
        message: `BuiltRight: Your assessment ${loanRequest.reference} is scheduled for ${scheduledDate.toLocaleString("en-NG", { dateStyle: "medium", timeStyle: "short" })} at ${normalizedLocation}. Fee: ${formatNaira(normalizedFee)}. Pay ${inspectionPaymentDetails.bank} ${inspectionPaymentDetails.accountNumber}, ${inspectionPaymentDetails.accountName}, then upload proof in your profile.`,
      });
    } catch (smsError) {
      console.error("INSPECTION SCHEDULE SMS ERROR:", smsError.message);
    }
    return res.json({ status: true, message: "Inspection scheduled. Email and SMS notifications were prepared for the customer.", loanRequest: sanitizeInstallerAssignment(loanRequest) });
  } catch (error) {
    console.error("ACCEPT INSTALLER ASSIGNMENT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not accept the inspection assignment." });
  }
});

app.patch("/api/installer/assignments/:id/payment-received", requireInstallerAuth, async (req, res) => {
  return res.status(403).json({ status: false, message: "Assessment payments are managed privately by the sales team." });
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
    return res.json({ status: true, message: replacement ? `Assignment reassigned to ${replacement.fullName}.` : "No alternate installer is currently active. An administrator must reassign this request.", loanRequest: sanitizeInstallerAssignment(loanRequest) });
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
    const { inspection = {}, loadAudit = {}, dueDiligence = {}, siteDetails = {}, inspectionCosts = [] } = req.body;
    const copyFields = (target, source, fields) => fields.forEach((field) => {
      if (Object.prototype.hasOwnProperty.call(source, field)) target[field] = source[field];
    });
    copyFields(loanRequest.assessment.inspection, inspection, ["status", "result", "notes"]);
    if (loanRequest.intake?.source !== "sales-whatsapp") {
      copyFields(loanRequest.assessment.loadAudit, loadAudit, ["status", "result", "peakLoadKw", "dailyEnergyKwh", "criticalLoadKw", "recommendedInverterKva", "recommendedBatteryKwh", "recommendedSolarKw", "backupHours", "appliances", "notes"]);
    }
    copyFields(loanRequest.assessment.dueDiligence, dueDiligence, ["status", "result", "checklist", "notes"]);
    copyFields(loanRequest.inspection, siteDetails, ["propertyType", "cableDistance", "mountingMethod", "notes"]);
    loanRequest.assessment.inspection.completedBy = loanRequest.installerAssignment.installerName;
    if (loanRequest.intake?.source !== "sales-whatsapp") {
      loanRequest.assessment.loadAudit.completedBy = loanRequest.installerAssignment.installerName;
    }
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
    await loanRequest.save();
    return res.json({
      status: true,
      message: loanRequest.assessment.status === "passed"
        ? "Site assessment saved. Sales can now download the full report and prepare the quotation."
        : "Installer site-assessment report saved.",
      loanRequest: sanitizeInstallerAssignment(loanRequest),
    });
  } catch (error) {
    console.error("INSTALLER REPORT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not save the installer report." });
  }
});

app.patch("/api/loan-requests/:id/assessment", requireOperationsAuth, async (req, res) => {
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

app.post("/api/loan-requests/:id/quotation", requireOperationsAuth, async (req, res) => {
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

app.post("/api/loan-requests/:id/quotation/:documentId/send", requireOperationsAuth, async (req, res) => {
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
    const portalUrl = `${frontendUrl()}/customer/documents`;

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

app.post("/api/loan-requests/:id/documents/:documentId/send", requireOperationsAuth, async (req, res) => {
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
      const portalUrl = `${frontendUrl()}/customer/documents`;
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
        createdOrder.source = "Financing";
        createdOrder.items = safeItems;
        createdOrder.amount = loanRequest.finalProjectCost ?? loanRequest.estimatedAmount ?? null;
        createdOrder.status = "Confirmed";
        await createdOrder.save();
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
        const portalUrl = `${frontendUrl()}/customer/documents`;
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
      .select("fullName email phone isActive installerProfile.availability")
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
    const { fullName, email, phone } = req.body;
    if (!fullName || !email || !phone) return res.status(400).json({ status: false, message: "Installer name, email, and phone number are required." });
    const existing = await User.findOne({ email: String(email).toLowerCase() });
    if (existing) return res.status(409).json({ status: false, message: "An account already uses this email address." });
    const installer = await makeInstallerInvite({ fullName: String(fullName).trim(), email: String(email).toLowerCase().trim(), phone: String(phone).trim() });
    return res.status(201).json({ status: true, message: "Installer invitation email sent.", installer: { id: installer._id, fullName: installer.fullName, email: installer.email, phone: installer.phone } });
  } catch (error) {
    console.error("CREATE INSTALLER ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not create installer." });
  }
});

app.patch("/api/admin/installers/:id/contact", requireAdminAuth, async (req, res) => {
  try {
    const phone = String(req.body.phone || "").trim();
    if (!phone) return res.status(400).json({ status: false, message: "Enter the installer's phone number." });
    const installer = await User.findOneAndUpdate(
      { _id: req.params.id, role: "installer" },
      { $set: { phone } },
      { new: true },
    ).select("fullName email phone isActive installerProfile.availability");
    if (!installer) return res.status(404).json({ status: false, message: "Installer not found." });
    return res.json({ status: true, message: "Installer phone number updated.", installer });
  } catch (error) {
    console.error("UPDATE INSTALLER CONTACT ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not update installer phone number." });
  }
});

app.get("/api/admin/sales-team", requireAdminAuth, async (req, res) => {
  try {
    const members = await User.find({ role: "sales" })
      .select("fullName email phone isActive createdAt salesProfile.activatedAt salesProfile.invitedAt salesProfile.invitationEmailSentAt")
      .sort({ createdAt: -1 })
      .lean();
    const withProjects = await Promise.all(members.map(async (member) => ({
      ...member,
      projectsCreated: await LoanRequest.countDocuments({ "intake.createdBy": member._id, "testRun.isTest": { $ne: true } }),
    })));
    return res.json({ status: true, members: withProjects });
  } catch (error) {
    console.error("GET SALES TEAM ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load the sales team." });
  }
});

app.post("/api/admin/sales-team", requireAdminAuth, async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const email = String(req.body.email || "").toLowerCase().trim();
    const phone = String(req.body.phone || "").trim();
    if (!fullName || !email) return res.status(400).json({ status: false, message: "Sales team member name and work email are required." });
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ status: false, message: "An account already uses this email address." });
    const member = await makeSalesInvite({ fullName, email, phone });
    return res.status(201).json({ status: true, message: "Sales invitation email sent.", member: { id: member._id, fullName: member.fullName, email: member.email } });
  } catch (error) {
    console.error("CREATE SALES MEMBER ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not invite the sales team member." });
  }
});

app.delete("/api/admin/sales-team/:id", requireAdminAuth, async (req, res) => {
  try {
    const member = await User.findOneAndDelete({ _id: req.params.id, role: "sales" });
    if (!member) return res.status(404).json({ status: false, message: "Sales team member not found." });
    return res.json({ status: true, message: "Sales account deleted. Existing customer project records were preserved." });
  } catch (error) {
    console.error("DELETE SALES MEMBER ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not delete the sales account." });
  }
});

app.get("/api/admin/learners", requireAdminAuth, async (req, res) => {
  try {
    const learners = await User.find({ role: "learner" })
      .select("fullName email phone isActive createdAt learnerProfile")
      .sort({ createdAt: -1 })
      .lean();
    return res.json({
      status: true,
      learners: learners.map((learner) => ({
        ...learner,
        learnerProfile: learner.learnerProfile ? {
          ...learner.learnerProfile,
          invitationToken: undefined,
        } : learner.learnerProfile,
      })),
    });
  } catch (error) {
    console.error("GET LEARNERS ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load learners." });
  }
});

app.post("/api/admin/learners", requireAdminAuth, async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const email = String(req.body.email || "").toLowerCase().trim();
    const phone = String(req.body.phone || "").trim();
    if (!fullName || !email || !phone) {
      return res.status(400).json({ status: false, message: "Learner name, phone number, and email are required." });
    }
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ status: false, message: "An account already uses this email address." });
    const learner = await makeLearnerInvite({ fullName, email, phone });
    return res.status(201).json({
      status: true,
      message: "Learner added and invitation email sent.",
      learner: { id: learner._id, fullName: learner.fullName, email: learner.email, phone: learner.phone },
    });
  } catch (error) {
    console.error("CREATE LEARNER ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not add learner." });
  }
});

app.delete("/api/admin/learners/:id", requireAdminAuth, async (req, res) => {
  try {
    const learner = await User.findOneAndDelete({ _id: req.params.id, role: "learner" });
    if (!learner) return res.status(404).json({ status: false, message: "Learner not found." });
    return res.json({ status: true, message: "Learner account deleted successfully." });
  } catch (error) {
    console.error("DELETE LEARNER ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not delete learner." });
  }
});

app.get("/api/admin/training-settings", requireAdminAuth, async (req, res) => {
  try {
    const settings = await TrainingSettings.findOne().lean();
    return res.json({
      status: true,
      settings: {
        cohortName: settings?.cohortName || "BuiltRight Solar Installation Training",
        liveClassUrl: settings?.liveClassUrl || "",
        brochureUrl: settings?.brochureUrl || "",
        meetingNumber: settings?.meetingNumber || "",
        meetingPasscode: settings?.meetingPasscode || "",
        liveSessionActive: Boolean(settings?.liveSessionActive),
        zoomSdkConfigured: zoomMeetingSdkConfigured,
      },
    });
  } catch (error) {
    console.error("GET TRAINING SETTINGS ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not load training settings." });
  }
});

app.patch("/api/admin/training-settings", requireAdminAuth, async (req, res) => {
  try {
    const payload = {
      cohortName: String(req.body.cohortName || "BuiltRight Solar Installation Training").trim(),
      liveClassUrl: String(req.body.liveClassUrl || "").trim(),
      brochureUrl: String(req.body.brochureUrl || "").trim(),
      meetingNumber: String(req.body.meetingNumber || "").replace(/\D/g, ""),
      meetingPasscode: String(req.body.meetingPasscode || "").trim(),
      liveSessionActive: req.body.liveSessionActive === true,
    };
    const settings = await TrainingSettings.findOneAndUpdate({}, payload, { new: true, upsert: true, setDefaultsOnInsert: true }).lean();
    return res.json({
      status: true,
      message: "Training settings saved.",
      settings: { ...settings, zoomSdkConfigured: zoomMeetingSdkConfigured },
    });
  } catch (error) {
    console.error("UPDATE TRAINING SETTINGS ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not save training settings." });
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

      const salesOwner = loanRequest.intake?.createdBy
        ? await User.findOne({ _id: loanRequest.intake.createdBy, role: "sales", isActive: true }).select("email fullName").lean()
        : null;
      const proofReviewEmail = salesOwner?.email || process.env.ADMIN_EMAIL;
      if (proofReviewEmail) {
        try {
          await sendEmail({
            to: proofReviewEmail,
            subject: `Assessment payment proof submitted - ${loanRequest.reference}`,
            html: `<h2>Assessment payment proof submitted</h2><p>${safeHtml(loanRequest.customer.fullName)} has uploaded payment proof.</p><p>Sign in to the sales portal to review and confirm it. The installer will not see the fee or the proof.</p><p><a href="${frontendUrl()}/sales/projects">Open sales projects</a></p>`,
          });
        } catch (mailError) {
          console.error("INSPECTION PROOF NOTIFICATION ERROR:", mailError.message);
        }
      }
      return res.json({ status: true, message: "Payment proof uploaded. The sales team will confirm receipt before the assessment begins.", loanRequest });
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
      .select("reference status quotation bankApplication deposit finalProjectCost paymentMethod installationProvider productSource financeInstitution assessment installerAssignment")
      .lean();
    const financingById = new Map(financingRequests.map((item) => [String(item._id), {
      ...item,
      bankApplication: {
        ...item.bankApplication,
        richGreenApplication: item.bankApplication?.richGreenApplication ? {
          status: item.bankApplication.richGreenApplication.status,
          submittedAt: item.bankApplication.richGreenApplication.submittedAt,
          submittedBy: item.bankApplication.richGreenApplication.submittedBy,
          quotationDocument: item.bankApplication.richGreenApplication.quotationDocument,
        } : null,
      },
    }]));

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
    const isRichGreen = !isOutright && /richgreen/i.test(String(loanRequest.financeInstitution || loanRequest.bankApplication?.provider || ""));
    const bankApplicationUrl = isOutright
      ? ""
      : (isRichGreen ? "" : (loanRequest.bankApplication?.redirectUrl || process.env.BANK_APPLICATION_URL || ""));
    const bankApplicationEmail = isOutright || isRichGreen ? "" : (process.env.BANK_APPLICATION_EMAIL || "");
    loanRequest.quotation.status = "approved";
    loanRequest.quotation.document = quotation._id;
    loanRequest.quotation.reference = quotation.reference;
    loanRequest.quotation.approvedAt = approvedAt;
    loanRequest.bankApplication.redirectUrl = bankApplicationUrl;
    loanRequest.bankApplication.quotationDocument = quotation._id;
    loanRequest.bankApplication.customerApprovedAt = approvedAt;
    loanRequest.bankApplication.status = isOutright
      ? "not-required"
      : (isRichGreen ? "manual-application-ready" : (bankApplicationUrl ? "ready-for-customer" : "awaiting-bank-link"));
    if (isRichGreen) {
      loanRequest.bankApplication.richGreenApplication ||= {};
      loanRequest.bankApplication.richGreenApplication.status = "ready";
      loanRequest.bankApplication.richGreenApplication.quotationDocument = quotation._id;
    }
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
        : (isRichGreen
          ? "Quotation approved. Complete the RichGreen credit application form now."
        : (bankApplicationUrl
          ? "Quotation approved. Your bank credit application is now available."
          : "Quotation approved. BuiltRight is awaiting the bank's hosted application link.")),
      quotation,
      bankApplication: {
        ready: Boolean(bankApplicationUrl),
        url: bankApplicationUrl,
        status: loanRequest.bankApplication.status,
        richGreenApplication: loanRequest.bankApplication.richGreenApplication,
      },
    });
  } catch (error) {
    console.error("APPROVE QUOTATION ERROR:", error.message);
    return res.status(500).json({ status: false, message: "Could not approve the quotation." });
  }
});

app.post("/api/customer/financing/:id/richgreen-application", requireCustomerAuth, async (req, res) => {
  try {
    const loanRequest = await LoanRequest.findOne({ _id: req.params.id, "customer.email": req.user.email });
    if (!loanRequest) return res.status(404).json({ status: false, message: "Financing project not found." });
    if (loanRequest.paymentMethod === "outright" || !/richgreen/i.test(String(loanRequest.financeInstitution || ""))) {
      return res.status(409).json({ status: false, message: "The RichGreen application is not available for this project." });
    }
    const quotation = await ProjectDocument.findOne({ financingRequest: loanRequest._id, type: "quotation", status: "approved" }).sort({ version: -1 });
    if (!quotation) return res.status(409).json({ status: false, message: "Approve the final quotation before completing the RichGreen application." });

    const source = req.body || {};
    const clean = (value) => String(value || "").trim();
    const application = {
      fullName: clean(source.fullName || loanRequest.customer?.fullName),
      dateOfBirth: clean(source.dateOfBirth),
      gender: clean(source.gender),
      maritalStatus: clean(source.maritalStatus),
      phoneNumber: clean(source.phoneNumber || loanRequest.customer?.phone),
      emailAddress: clean(source.emailAddress || loanRequest.customer?.email).toLowerCase(),
      residentialAddress: clean(source.residentialAddress),
      state: clean(source.state),
      lga: clean(source.lga),
      bvn: clean(source.bvn).replace(/\D/g, ""),
      nin: clean(source.nin).replace(/\D/g, ""),
      identificationType: clean(source.identificationType),
      identificationNumber: clean(source.identificationNumber),
      identificationExpiryDate: clean(source.identificationExpiryDate),
      employmentStatus: clean(source.employmentStatus),
      employerBusinessName: clean(source.employerBusinessName),
      officeBusinessAddress: clean(source.officeBusinessAddress),
      positionBusinessType: clean(source.positionBusinessType),
      monthlyNetIncome: Number(source.monthlyNetIncome || 0),
      yearsInEmploymentBusiness: clean(source.yearsInEmploymentBusiness),
      bankName: clean(source.bankName),
      accountNumber: clean(source.accountNumber).replace(/\D/g, ""),
      accountName: clean(source.accountName),
      preferredRepaymentMethod: clean(source.preferredRepaymentMethod),
      packageSelected: clean(source.packageSelected || quotation.project?.systemName),
      systemCapacity: clean(source.systemCapacity || quotation.project?.systemCapacity),
      preferredRepaymentTenor: Number(source.preferredRepaymentTenor || 0),
      installationAddress: clean(source.installationAddress || quotation.project?.siteAddress || loanRequest.customer?.location),
      guarantorName: clean(source.guarantorName),
      guarantorPhoneNumber: clean(source.guarantorPhoneNumber),
      guarantorOccupation: clean(source.guarantorOccupation),
      guarantorResidentialAddress: clean(source.guarantorResidentialAddress),
      guarantorRelationship: clean(source.guarantorRelationship),
      applicantName: clean(source.applicantName),
      electronicSignature: clean(source.electronicSignature),
      declarationAccepted: Boolean(source.declarationAccepted),
    };
    const requiredFields = [
      ["fullName", "full name"], ["dateOfBirth", "date of birth"], ["gender", "gender"], ["maritalStatus", "marital status"],
      ["phoneNumber", "phone number"], ["emailAddress", "email address"], ["residentialAddress", "residential address"],
      ["state", "state"], ["lga", "LGA"], ["bvn", "BVN"], ["identificationType", "identification type"],
      ["identificationNumber", "identification number"], ["identificationExpiryDate", "identification expiry date"],
      ["employmentStatus", "employment status"], ["employerBusinessName", "employer or business name"],
      ["officeBusinessAddress", "office or business address"], ["positionBusinessType", "position or business type"],
      ["yearsInEmploymentBusiness", "years in employment or business"], ["bankName", "bank name"],
      ["accountNumber", "account number"], ["accountName", "account name"],
      ["preferredRepaymentMethod", "preferred repayment method"], ["packageSelected", "package selected"],
      ["systemCapacity", "system capacity"], ["installationAddress", "installation address"],
      ["applicantName", "applicant name"], ["electronicSignature", "electronic signature"],
    ];
    const missing = requiredFields.find(([key]) => !application[key]);
    if (missing) return res.status(400).json({ status: false, message: `Enter the applicant's ${missing[1]}.` });
    if (!/^\d{11}$/.test(application.bvn)) return res.status(400).json({ status: false, message: "Enter a valid 11-digit BVN." });
    if (application.nin && !/^\d{11}$/.test(application.nin)) return res.status(400).json({ status: false, message: "Enter a valid 11-digit NIN or leave it blank." });
    if (!/^\d{10}$/.test(application.accountNumber)) return res.status(400).json({ status: false, message: "Enter a valid 10-digit bank account number." });
    if (!(application.monthlyNetIncome > 0)) return res.status(400).json({ status: false, message: "Enter the applicant's monthly net income." });
    if (![3, 4, 5, 6, 7].includes(application.preferredRepaymentTenor)) return res.status(400).json({ status: false, message: "Select a repayment tenor from 3 to 7 months." });
    if (/business owner/i.test(application.employmentStatus)) {
      const guarantorFields = ["guarantorName", "guarantorPhoneNumber", "guarantorOccupation", "guarantorResidentialAddress", "guarantorRelationship"];
      if (guarantorFields.some((key) => !application[key])) return res.status(400).json({ status: false, message: "Complete all guarantor details for a business-owner application." });
    }
    if (!application.declarationAccepted) return res.status(400).json({ status: false, message: "Accept the customer declaration before submitting." });

    const submittedAt = new Date();
    loanRequest.bankApplication ||= {};
    loanRequest.bankApplication.status = "manual-application-submitted";
    loanRequest.bankApplication.richGreenApplication = {
      status: "submitted",
      submittedAt,
      submittedBy: application.fullName,
      quotationDocument: quotation._id,
      data: encryptApplicationData(application),
    };
    loanRequest.statusHistory.push({ status: loanRequest.status, source: "customer", note: `Customer submitted the RichGreen application for quotation ${quotation.reference}.` });
    await loanRequest.save();
    return res.json({
      status: true,
      message: "RichGreen application submitted securely. The sales team can now download it from the portal and forward it to the bank with your approved quotation.",
      richGreenApplication: { status: "submitted", submittedAt, submittedBy: application.fullName, quotationDocument: quotation._id },
    });
  } catch (error) {
    console.error("SUBMIT RICHGREEN APPLICATION ERROR:", error.message);
    return res.status(500).json({ status: false, message: error.message === "Application-data encryption is not configured." ? "Secure application storage is not configured. Contact BuiltRight support." : "Could not submit the RichGreen application." });
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
      loanRequest.assessment.status = "in-progress";
      loanRequest.assessment.loadAudit.status = "in-progress";
      loanRequest.assessment.loadAudit.result = "pending";
      loanRequest.assessment.loadAudit.completedAt = null;
      if (loanRequest.installerAssignment?.installer) {
        loanRequest.installerAssignment.status = "accepted";
        loanRequest.installerAssignment.history.push({
          installer: loanRequest.installerAssignment.installer,
          installerName: loanRequest.installerAssignment.installerName,
          status: "accepted",
          note: `Load-audit revision reopened after customer declined quotation ${quotation.reference}.`,
          changedAt: new Date(),
        });
      }
      loanRequest.status = "under-assessment";
      loanRequest.statusHistory.push({
        status: "under-assessment",
        source: "customer",
        note: `Customer declined quotation ${quotation.reference} and requested a load/system review: ${note}`,
      });
      await loanRequest.save();
    }

    try {
      const salesEmail = loanRequest?.intake?.createdByEmail || process.env.ADMIN_ALERT_EMAIL || process.env.SMTP_USER;
      await sendEmail({
        to: salesEmail,
        subject: `Quotation declined - load review required - ${quotation.reference}`,
        html: `<h2>Customer requested a lower-load system review</h2><p>${escapeHtml(quotation.customer.fullName)} declined ${escapeHtml(quotation.reference)} and requested a review.</p><p><strong>Customer reason:</strong> ${escapeHtml(note)}</p><p>Contact the assigned installer, revise the load audit and recommendation, then prepare and send a new quotation.</p><p><strong>Assigned installer:</strong> ${escapeHtml(loanRequest?.installerAssignment?.installerName || "Not assigned")}</p><p><a href="${frontendUrl()}/sales/projects/${loanRequest?._id}">Open project workspace</a></p>`,
      });
    } catch (mailError) {
      console.error("QUOTATION CHANGE EMAIL ERROR:", mailError.message);
    }

    return res.json({ status: true, message: "Your quotation was declined and the review request was sent to the sales team. They will work with the installer on a revised load and system recommendation.", quotation });
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
    release: "2026-10-23-password-visibility-and-recovery-v2",
    portalUrl: frontendUrl(),
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
