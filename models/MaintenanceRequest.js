import mongoose from "mongoose";

const requestTimelineSchema = new mongoose.Schema(
  {
    status: { type: String, required: true },
    note: { type: String, default: "", trim: true },
    source: { type: String, enum: ["customer", "admin", "system"], default: "system" },
    actorName: { type: String, default: "", trim: true },
    at: { type: Date, default: Date.now },
  },
  { _id: false }
);

const maintenanceRequestSchema = new mongoose.Schema(
  {
    reference: { type: String, required: true, unique: true, index: true },
    property: { type: mongoose.Schema.Types.ObjectId, ref: "MaintenanceProperty", required: true, index: true },
    customer: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    customerSnapshot: {
      fullName: { type: String, default: "" },
      email: { type: String, default: "", lowercase: true },
      phone: { type: String, default: "" },
    },
    requestType: { type: String, enum: ["service", "emergency"], default: "service" },
    category: {
      type: String,
      enum: ["electrical", "plumbing", "air-conditioning", "fire-safety", "security", "generator", "lift", "building", "other"],
      default: "other",
    },
    priority: { type: String, enum: ["low", "normal", "high", "emergency"], default: "normal" },
    status: {
      type: String,
      enum: ["submitted", "acknowledged", "team-assigned", "en-route", "in-progress", "resolved", "closed", "cancelled"],
      default: "submitted",
      index: true,
    },
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    locationWithinProperty: { type: String, default: "", trim: true },
    safeToRemainOnSite: { type: Boolean, default: true },
    assignedTeam: { type: String, default: "", trim: true },
    responseNote: { type: String, default: "", trim: true },
    acknowledgedAt: { type: Date, default: null },
    dispatchedAt: { type: Date, default: null },
    resolvedAt: { type: Date, default: null },
    timeline: { type: [requestTimelineSchema], default: [] },
  },
  { timestamps: true }
);

maintenanceRequestSchema.index({ property: 1, createdAt: -1 });
maintenanceRequestSchema.index({ customer: 1, createdAt: -1 });

export default mongoose.model("MaintenanceRequest", maintenanceRequestSchema);
