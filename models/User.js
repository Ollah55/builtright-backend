import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    phone: {
      type: String,
      required: function requiresPhone() {
        return this.role === "customer";
      },
      default: "",
      trim: true,
    },
    location: {
      type: String,
      default: "",
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["customer", "admin", "installer", "learner"],
      default: "customer",
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    installerProfile: {
      availability: {
        type: String,
        enum: ["available", "unavailable"],
        default: "available",
      },
      invitationToken: { type: String, default: "" },
      invitationExpiresAt: { type: Date, default: null },
      invitedAt: { type: Date, default: null },
      invitationEmailSentAt: { type: Date, default: null },
      domainLinkReissuedAt: { type: Date, default: null },
      domainLinkReissueVersion: { type: String, default: "" },
      activatedAt: { type: Date, default: null },
    },
    learnerProfile: {
      invitationToken: { type: String, default: "" },
      invitationExpiresAt: { type: Date, default: null },
      invitedAt: { type: Date, default: null },
      invitationEmailSentAt: { type: Date, default: null },
      activatedAt: { type: Date, default: null },
      cohortName: { type: String, default: "BuiltRight Solar Installation Training" },
      cohortStart: { type: Date, default: null },
      cohortEnd: { type: Date, default: null },
      enrollmentStatus: {
        type: String,
        enum: ["invited", "active", "completed", "suspended"],
        default: "invited",
      },
    },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

export default User;
