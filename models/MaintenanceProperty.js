import mongoose from "mongoose";

const maintenanceAssetSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    category: {
      type: String,
      enum: ["electrical", "plumbing", "air-conditioning", "fire-safety", "security", "generator", "lift", "building", "other"],
      default: "other",
    },
    condition: {
      type: String,
      enum: ["good", "attention", "critical", "out-of-service"],
      default: "good",
    },
    lastServicedAt: { type: Date, default: null },
    nextServiceAt: { type: Date, default: null },
    notes: { type: String, default: "", trim: true },
  },
  { _id: true }
);

const maintenanceVisitSchema = new mongoose.Schema(
  {
    type: { type: String, enum: ["inspection", "preventive", "corrective", "emergency", "other"], default: "preventive" },
    scheduledFor: { type: Date, default: null },
    completedAt: { type: Date, default: null },
    status: { type: String, enum: ["scheduled", "in-progress", "completed", "cancelled"], default: "scheduled" },
    summary: { type: String, default: "", trim: true },
    technician: { type: String, default: "", trim: true },
  },
  { _id: true }
);

const maintenancePropertySchema = new mongoose.Schema(
  {
    reference: { type: String, required: true, unique: true, index: true },
    customer: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    customerSnapshot: {
      fullName: { type: String, default: "" },
      email: { type: String, default: "", lowercase: true },
      phone: { type: String, default: "" },
    },
    property: {
      name: { type: String, required: true, trim: true },
      type: {
        type: String,
        enum: ["apartment", "residential-building", "office", "school", "hotel", "retail", "industrial", "estate", "other"],
        default: "other",
      },
      address: { type: String, required: true, trim: true },
      city: { type: String, default: "Lagos", trim: true },
      state: { type: String, default: "Lagos", trim: true },
      landmark: { type: String, default: "", trim: true },
      contactPerson: { type: String, default: "", trim: true },
      contactPhone: { type: String, default: "", trim: true },
    },
    subscription: {
      plan: { type: String, enum: ["bronze", "silver", "gold", "platinum", "custom"], default: "bronze" },
      status: { type: String, enum: ["pending", "probation", "active", "paused", "expired", "cancelled"], default: "pending" },
      billingCycle: { type: String, enum: ["monthly", "quarterly", "biannual", "annual", "custom"], default: "monthly" },
      amount: { type: Number, default: 0, min: 0 },
      startsAt: { type: Date, default: null },
      endsAt: { type: Date, default: null },
      nextRenewalAt: { type: Date, default: null },
      coveredServices: [{ type: String, trim: true }],
      notes: { type: String, default: "", trim: true },
    },
    onboarding: {
      stage: {
        type: String,
        enum: [
          "site-inspection-pending",
          "site-inspection-scheduled",
          "due-diligence-in-progress",
          "remediation-required",
          "remediation-in-progress",
          "remediation-completed",
          "probation-payment-due",
          "probation-active",
          "probation-review",
          "contract-active",
          "terminated",
        ],
        default: "site-inspection-pending",
      },
      inspection: {
        scheduledAt: { type: Date, default: null },
        completedAt: { type: Date, default: null },
        findings: { type: String, default: "", trim: true },
        dueDiligenceNotes: { type: String, default: "", trim: true },
      },
      remediation: {
        required: { type: Boolean, default: false },
        status: { type: String, enum: ["not-assessed", "not-required", "required", "in-progress", "completed"], default: "not-assessed" },
        scope: { type: String, default: "", trim: true },
        completedAt: { type: Date, default: null },
      },
      probation: {
        paymentStatus: { type: String, enum: ["pending", "paid"], default: "pending" },
        amount: { type: Number, default: 0, min: 0 },
        paidAt: { type: Date, default: null },
        startsAt: { type: Date, default: null },
        endsAt: { type: Date, default: null },
        nonRefundable: { type: Boolean, default: true },
        outcome: { type: String, enum: ["pending", "continue", "terminate"], default: "pending" },
        reviewNotes: { type: String, default: "", trim: true },
      },
      contractActivatedAt: { type: Date, default: null },
      terminatedAt: { type: Date, default: null },
    },
    health: {
      status: { type: String, enum: ["healthy", "attention", "critical", "assessment-pending"], default: "assessment-pending" },
      score: { type: Number, default: 0, min: 0, max: 100 },
      summary: { type: String, default: "Initial facility assessment is pending.", trim: true },
      lastAssessmentAt: { type: Date, default: null },
      updatedAt: { type: Date, default: Date.now },
    },
    assets: { type: [maintenanceAssetSchema], default: [] },
    visits: { type: [maintenanceVisitSchema], default: [] },
    isActive: { type: Boolean, default: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  },
  { timestamps: true }
);

maintenancePropertySchema.index({ customer: 1, isActive: 1 });
maintenancePropertySchema.index({ "subscription.status": 1, "health.status": 1 });

export default mongoose.model("MaintenanceProperty", maintenancePropertySchema);
