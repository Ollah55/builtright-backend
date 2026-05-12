import mongoose from "mongoose";

const loanRequestSchema = new mongoose.Schema(
  {
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
    },

    productSource: {
      type: String,
      enum: ["BuiltRight Marketplace", "External Vendor"],
      default: "BuiltRight Marketplace",
    },

    financeInstitution: {
      type: String,
      enum: [
        "Rich Green Microfinance Bank",
        "Premium Trust Bank",
        "Zenith Bank",
      ],
      default: "Rich Green Microfinance Bank",
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
    "pending",
    "contacted",
    "sent-to-bank",
    "under-assessment",
    "approved",
    "declined",
    "installation-scheduled",
    "completed",
  ],
  default: "pending",
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