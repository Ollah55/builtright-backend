import mongoose from "mongoose";

const deviceAlertSchema = new mongoose.Schema(
  {
    reference: {
      type: String,
      required: true,
      unique: true,
      uppercase: true,
      trim: true,
    },
    device: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Device",
      required: true,
      index: true,
    },
    deviceReference: { type: String, required: true, uppercase: true, trim: true },
    providerEventId: { type: String, default: "", trim: true },
    type: {
      type: String,
      enum: [
        "tamper",
        "cable-disconnected",
        "offline",
        "connectivity-restored",
        "default",
        "grace-period",
        "command-failed",
        "other",
      ],
      required: true,
    },
    severity: {
      type: String,
      enum: ["info", "warning", "critical"],
      default: "warning",
    },
    status: {
      type: String,
      enum: ["open", "acknowledged", "resolved"],
      default: "open",
      index: true,
    },
    source: {
      type: String,
      enum: ["provider-webhook", "manual", "system"],
      default: "system",
    },
    occurredAt: { type: Date, default: Date.now },
    acknowledgedAt: { type: Date, default: null },
    acknowledgedBy: { type: String, default: "", trim: true },
    resolvedAt: { type: Date, default: null },
    resolvedBy: { type: String, default: "", trim: true },
    title: { type: String, required: true, trim: true },
    detail: { type: String, default: "", trim: true },
    evidence: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true }
);

deviceAlertSchema.index({ device: 1, occurredAt: -1 });

const DeviceAlert = mongoose.model("DeviceAlert", deviceAlertSchema);

export default DeviceAlert;
