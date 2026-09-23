import mongoose from "mongoose";

const accountingAssetSchema = new mongoose.Schema({
  assetCode: { type: String, required: true, unique: true, trim: true, uppercase: true },
  name: { type: String, required: true, trim: true },
  acquisitionDate: { type: Date, default: null },
  costKobo: { type: Number, required: true, min: 0 },
  category: { type: String, default: "Unassigned", trim: true },
  location: { type: String, default: "", trim: true },
  condition: { type: String, default: "", trim: true },
  usefulLifeMonths: { type: Number, default: null, min: 1, max: 600 },
  residualValueKobo: { type: Number, default: 0, min: 0 },
  openingAccumulatedDepreciationKobo: { type: Number, default: 0, min: 0 },
  status: { type: String, enum: ["review-required", "active", "disposed"], default: "review-required" },
  notes: { type: String, default: "", trim: true },
  sourceFile: { type: String, default: "", trim: true },
  sourceRow: { type: Number, default: null, min: 1 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
}, { timestamps: true });

accountingAssetSchema.index({ status: 1, assetCode: 1 });

export default mongoose.model("AccountingAsset", accountingAssetSchema);
