import mongoose from "mongoose";

const deviceCommandSchema = new mongoose.Schema(
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
    action: { type: String, enum: ["on", "off"], required: true },
    status: {
      type: String,
      enum: ["blocked", "pending", "sent", "acknowledged", "failed", "cancelled"],
      default: "pending",
      index: true,
    },
    requestedBy: {
      id: { type: String, default: "", trim: true },
      email: { type: String, default: "", trim: true },
    },
    reason: { type: String, required: true, trim: true },
    provider: { type: String, default: "AshGridX", trim: true },
    providerReference: { type: String, default: "", trim: true },
    policySnapshot: {
      paymentStanding: { type: String, default: "unknown" },
      gracePeriodEndsAt: { type: Date, default: null },
      defaultVerifiedAt: { type: Date, default: null },
      communicationsCompletedAt: { type: Date, default: null },
      deviceConnectivity: { type: String, default: "unknown" },
      humanConfirmed: { type: Boolean, default: false },
    },
    blockedReason: { type: String, default: "", trim: true },
    sentAt: { type: Date, default: null },
    acknowledgedAt: { type: Date, default: null },
    failureCode: { type: String, default: "", trim: true },
    failureMessage: { type: String, default: "", trim: true },
  },
  { timestamps: true }
);

deviceCommandSchema.index({ device: 1, createdAt: -1 });

const DeviceCommand = mongoose.model("DeviceCommand", deviceCommandSchema);

export default DeviceCommand;
