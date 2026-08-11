import mongoose from "mongoose";

const loanRequestSchema = new mongoose.Schema(
  {
    reference: {
      type: String,
      default: () => `BRF-${Date.now().toString().slice(-8)}`,
      index: true,
    },

    customer: {
      fullName: {
        type: String,
        required: true,
        trim: true,
      },
      email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
      },
      phone: {
        type: String,
        required: true,
        trim: true,
      },
      location: {
        type: String,
        default: "",
        trim: true,
      },
    },

    productSource: {
      type: String,
      enum: ["BuiltRight Marketplace", "External Vendor"],
      default: "BuiltRight Marketplace",
    },

    financeInstitution: {
      type: String,
      default: "Bank partner pending",
      trim: true,
    },

    interestRate: {
      type: String,
      default: "",
      trim: true,
    },

    loanTenor: {
      type: String,
      default: "",
      trim: true,
    },

    depositRequired: {
      type: String,
      default: "",
      trim: true,
    },

    vendorName: {
      type: String,
      default: "",
      trim: true,
    },

    vendorContact: {
      type: String,
      default: "",
      trim: true,
    },

    vendorProductDetails: {
      type: String,
      default: "",
      trim: true,
    },

  items: {
  type: [
    {
      id: {
        type: String,
        default: "",
      },

      name: {
        type: String,
        default: "Selected Product",
      },

      quantity: {
        type: Number,
        default: 1,
      },

      price: {
        type: Number,
        default: null,
      },

      supplier: {
        type: String,
        default: "",
      },

      manufacturer: {
        type: String,
        default: "",
      },

      category: {
        type: String,
        default: "",
      },

      type: {
        type: String,
        default: "",
      },

      capacity: {
        type: String,
        default: "",
      },

      image: {
        type: String,
        default: "",
      },
    },
  ],
  default: [],
},

    estimatedAmount: {
      type: Number,
      default: null,
    },

    finalProjectCost: {
      type: Number,
      default: null,
    },

    upfrontCosts: {
      type: [
        {
          label: { type: String, default: "" },
          amount: { type: Number, default: null },
          confirmed: { type: Boolean, default: false },
        },
      ],
      default: [],
    },

    inspectionCosts: {
      type: [
        {
          label: { type: String, default: "" },
          amount: { type: Number, default: null },
        },
      ],
      default: [],
    },

    inspection: {
      status: { type: String, default: "not-scheduled" },
      scheduledAt: { type: Date, default: null },
      completedAt: { type: Date, default: null },
      assignee: { type: String, default: "" },
      propertyType: { type: String, default: "" },
      cableDistance: { type: String, default: "" },
      mountingMethod: { type: String, default: "" },
      notes: { type: String, default: "" },
      feeAmount: { type: Number, default: null },
      feeStatus: { type: String, default: "not-requested" },
    },

    installerAssignment: {
      installer: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
      installerName: { type: String, default: "", trim: true },
      installerEmail: { type: String, default: "", trim: true, lowercase: true },
      status: {
        type: String,
        enum: ["unassigned", "assigned", "accepted", "scheduled", "declined", "completed"],
        default: "unassigned",
      },
      assignedAt: { type: Date, default: null },
      acceptedAt: { type: Date, default: null },
      declinedAt: { type: Date, default: null },
      declineReason: { type: String, default: "", trim: true },
      reassignmentCount: { type: Number, default: 0 },
      history: {
        type: [
          {
            installer: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            installerName: { type: String, default: "" },
            status: { type: String, default: "assigned" },
            note: { type: String, default: "" },
            changedAt: { type: Date, default: Date.now },
          },
        ],
        default: [],
      },
    },

    assessment: {
      status: {
        type: String,
        enum: ["open", "in-progress", "passed", "failed"],
        default: "open",
      },
      triggeredAt: { type: Date, default: Date.now },
      inspection: {
        status: {
          type: String,
          enum: ["pending", "scheduled", "completed", "failed"],
          default: "pending",
        },
        result: {
          type: String,
          enum: ["pending", "pass", "fail"],
          default: "pending",
        },
        completedAt: { type: Date, default: null },
        completedBy: { type: String, default: "", trim: true },
        notes: { type: String, default: "", trim: true },
      },
      loadAudit: {
        status: {
          type: String,
          enum: ["pending", "in-progress", "completed", "failed"],
          default: "pending",
        },
        result: {
          type: String,
          enum: ["pending", "pass", "fail"],
          default: "pending",
        },
        peakLoadKw: { type: Number, default: null },
        dailyEnergyKwh: { type: Number, default: null },
        criticalLoadKw: { type: Number, default: null },
        recommendedInverterKva: { type: Number, default: null },
        recommendedBatteryKwh: { type: Number, default: null },
        recommendedSolarKw: { type: Number, default: null },
        backupHours: { type: Number, default: null },
        appliances: {
          type: [
            {
              name: { type: String, default: "", trim: true },
              quantity: { type: Number, default: 1 },
              watts: { type: Number, default: 0 },
              hoursPerDay: { type: Number, default: 0 },
              critical: { type: Boolean, default: false },
            },
          ],
          default: [],
        },
        completedAt: { type: Date, default: null },
        completedBy: { type: String, default: "", trim: true },
        notes: { type: String, default: "", trim: true },
      },
      dueDiligence: {
        status: {
          type: String,
          enum: ["pending", "in-progress", "completed", "failed"],
          default: "pending",
        },
        result: {
          type: String,
          enum: ["pending", "pass", "fail"],
          default: "pending",
        },
        checklist: {
          type: [
            {
              key: { type: String, required: true, trim: true },
              label: { type: String, required: true, trim: true },
              status: {
                type: String,
                enum: ["pending", "pass", "fail", "not-applicable"],
                default: "pending",
              },
              note: { type: String, default: "", trim: true },
            },
          ],
          default: [],
        },
        completedAt: { type: Date, default: null },
        completedBy: { type: String, default: "", trim: true },
        notes: { type: String, default: "", trim: true },
      },
    },

    quotation: {
      status: {
        type: String,
        enum: ["not-started", "draft", "sent", "approved", "changes-requested", "expired", "void"],
        default: "not-started",
      },
      document: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "ProjectDocument",
        default: null,
      },
      reference: { type: String, default: "", trim: true },
      version: { type: Number, default: 0 },
      sentAt: { type: Date, default: null },
      approvedAt: { type: Date, default: null },
      changesRequestedAt: { type: Date, default: null },
    },

    bankApplication: {
      provider: { type: String, default: "" },
      externalReference: { type: String, default: "" },
      status: { type: String, default: "not-started" },
      redirectUrl: { type: String, default: "" },
      approvedAmount: { type: Number, default: null },
      disbursedAmount: { type: Number, default: null },
      disbursedAt: { type: Date, default: null },
      quotationDocument: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "ProjectDocument",
        default: null,
      },
      quotationSharedAt: { type: Date, default: null },
      customerApprovedAt: { type: Date, default: null },
    },

    deposit: {
      percentage: { type: Number, default: 20 },
      amount: { type: Number, default: null },
      status: { type: String, default: "not-due" },
      paidAt: { type: Date, default: null },
    },

    preferredContact: {
      type: String,
      default: "WhatsApp",
    },

    consentToShare: {
      type: Boolean,
      default: false,
    },

    thirdPartyNoticeAccepted: {
      type: Boolean,
      default: false,
    },

    status: {
  type: String,
  enum: [
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
  ],
  default: "submitted",
},

    statusHistory: {
      type: [
        {
          status: { type: String, required: true },
          source: { type: String, default: "admin" },
          note: { type: String, default: "" },
          changedAt: { type: Date, default: Date.now },
        },
      ],
      default: [],
    },

    notes: {
      type: String,
      default: "",
    },
  },
  {
    timestamps: true,
  }
);

const LoanRequest = mongoose.model("LoanRequest", loanRequestSchema);

export default LoanRequest;
