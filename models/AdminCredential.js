import mongoose from "mongoose";

const adminCredentialSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, default: "" },
    passwordResetTokenHash: { type: String, default: "" },
    passwordResetExpiresAt: { type: Date, default: null },
    passwordResetSentAt: { type: Date, default: null },
  },
  { timestamps: true }
);

const AdminCredential = mongoose.model("AdminCredential", adminCredentialSchema);

export default AdminCredential;
