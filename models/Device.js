import mongoose from "mongoose";

const communicationSchema = new mongoose.Schema(
  {
    channel: {
      type: String,
      enum: ["sms", "email", "phone", "whatsapp", "other"],
      required: true,
    },
    sentAt: { type: Date, default: Date.now },
    note: { type: String, default: "", trim: true },
  },
  { _id: false }
);

const deviceSchema = new mongoose.Schema(
  {
    reference: {
      type: String,
      required: true,
      unique: true,
      uppercase: true,
      trim: true,
    },
    provider: { type: String, default: "AshGridX", trim: true },
    providerDeviceId: {
      type: String,
      trim: true,
      index: { unique: true, sparse: true },
    },
    serialNumber: { type: String, default: "", trim: true },
    label: { type: String, default: "Financed solar asset", trim: true },

    customer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    customerSnapshot: {
      fullName: { type: String, default: "", trim: true },
      email: { type: String, default: "", trim: true, lowercase: true },
      phone: { type: String, default: "", trim: true },
    },
    financingRequest: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "LoanRequest",
      default: null,
    },
    order: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Order",
      default: null,
    },
    projectReference: { type: String, default: "", trim: true },
    site: {
      address: { type: String, default: "", trim: true },
      city: { type: String, default: "", trim: true },
      state: { type: String, default: "Lagos", trim: true },
      installationNotes: { type: String, default: "", trim: true },
    },

    assignmentStatus: {
      type: String,
      enum: ["unassigned", "pending", "assigned", "decommissioned"],
      default: "unassigned",
    },
    connectivity: {
      type: String,
      enum: ["unknown", "online", "offline"],
      default: "unknown",
    },
    inverterState: {
      type: String,
      enum: ["unknown", "on", "off"],
      default: "unknown",
    },
    lastSeenAt: { type: Date, default: null },
    lastProviderSyncAt: { type: Date, default: null },

    tamper: {
      status: {
        type: String,
        enum: ["clear", "suspected", "confirmed"],
        default: "clear",
      },
      eventType: { type: String, default: "", trim: true },
      detectedAt: { type: Date, default: null },
      acknowledgedAt: { type: Date, default: null },
      notes: { type: String, default: "", trim: true },
    },

    paymentStanding: {
      type: String,
      enum: ["unknown", "current", "grace-period", "default-eligible", "cleared"],
      default: "unknown",
    },
    defaultVerifiedAt: { type: Date, default: null },
    gracePeriod: {
      startedAt: { type: Date, default: null },
      endsAt: { type: Date, default: null },
      days: { type: Number, default: 10, min: 1 },
      communicationsCompletedAt: { type: Date, default: null },
      communications: { type: [communicationSchema], default: [] },
    },

    installedAt: { type: Date, default: null },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true }
);

deviceSchema.index({ customer: 1, assignmentStatus: 1 });
deviceSchema.index({ connectivity: 1, "tamper.status": 1 });

const Device = mongoose.model("Device", deviceSchema);

export default Device;
