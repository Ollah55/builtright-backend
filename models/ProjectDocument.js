import mongoose from "mongoose";

const lineItemSchema = new mongoose.Schema(
  {
    category: {
      type: String,
      enum: [
        "solar-system",
        "installation-service",
        "insurance-compliance",
        "iot-tracking",
        "maintenance",
        "installation-materials",
        "mounting-materials",
        "cables",
        "protection-accessories",
        "civil-electrical-work",
        "discount",
        "other",
      ],
      default: "other",
    },
    description: { type: String, required: true, trim: true },
    quantity: { type: Number, default: 1, min: 0 },
    unit: { type: String, default: "item", trim: true },
    unitPrice: { type: Number, default: 0 },
    amount: { type: Number, default: 0 },
    source: {
      type: String,
      enum: ["confirmed", "inspection", "manual"],
      default: "manual",
    },
  },
  { _id: true }
);

const projectDocumentSchema = new mongoose.Schema(
  {
    reference: {
      type: String,
      required: true,
      unique: true,
      uppercase: true,
      trim: true,
    },
    financingRequest: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "LoanRequest",
      required: true,
      index: true,
    },
    order: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Order",
      default: null,
    },
    type: {
      type: String,
      enum: ["quotation", "invoice"],
      required: true,
      index: true,
    },
    version: { type: Number, default: 1, min: 1 },
    status: {
      type: String,
      enum: ["draft", "sent", "approved", "changes-requested", "issued", "expired", "void"],
      default: "draft",
      index: true,
    },
    title: { type: String, required: true, trim: true },
    customer: {
      fullName: { type: String, required: true, trim: true },
      email: { type: String, required: true, lowercase: true, trim: true },
      phone: { type: String, default: "", trim: true },
      location: { type: String, default: "", trim: true },
    },
    project: {
      systemName: { type: String, default: "", trim: true },
      systemCapacity: { type: String, default: "", trim: true },
      propertyType: { type: String, default: "", trim: true },
      cableDistance: { type: String, default: "", trim: true },
      mountingMethod: { type: String, default: "", trim: true },
      siteAddress: { type: String, default: "", trim: true },
      scope: { type: String, default: "", trim: true },
    },
    lineItems: { type: [lineItemSchema], default: [] },
    subtotal: { type: Number, default: 0 },
    tax: { type: Number, default: 0 },
    discount: { type: Number, default: 0 },
    total: { type: Number, default: 0 },
    equityPercentage: { type: Number, default: 20 },
    equityAmount: { type: Number, default: 0 },
    bankFinanceAmount: { type: Number, default: 0 },
    currency: { type: String, default: "NGN" },
    terms: { type: String, default: "", trim: true },
    notes: { type: String, default: "", trim: true },
    validUntil: { type: Date, default: null },
    sentAt: { type: Date, default: null },
    emailDelivery: {
      status: {
        type: String,
        enum: ["not-sent", "sent", "failed"],
        default: "not-sent",
      },
      sentAt: { type: Date, default: null },
      error: { type: String, default: "", trim: true },
    },
    customerDecision: {
      status: {
        type: String,
        enum: ["pending", "approved", "changes-requested"],
        default: "pending",
      },
      decidedAt: { type: Date, default: null },
      note: { type: String, default: "", trim: true },
    },
    bankDelivery: {
      status: {
        type: String,
        enum: ["not-ready", "pending", "sent", "failed"],
        default: "not-ready",
      },
      sentAt: { type: Date, default: null },
      error: { type: String, default: "", trim: true },
    },
    createdBy: { type: String, default: "BuiltRight operations", trim: true },
  },
  { timestamps: true }
);

projectDocumentSchema.index({ financingRequest: 1, type: 1, version: -1 });
projectDocumentSchema.index({ "customer.email": 1, createdAt: -1 });

const ProjectDocument = mongoose.model("ProjectDocument", projectDocumentSchema);

export default ProjectDocument;
