import mongoose from "mongoose";

const accountingAccountSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true, trim: true, uppercase: true },
  name: { type: String, required: true, trim: true },
  type: { type: String, required: true, enum: ["asset", "liability", "equity", "revenue", "expense"] },
  normalSide: { type: String, required: true, enum: ["debit", "credit"] },
  description: { type: String, default: "", trim: true },
  isActive: { type: Boolean, default: true },
}, { timestamps: true });

export default mongoose.model("AccountingAccount", accountingAccountSchema);
