import mongoose from "mongoose";

const journalLineSchema = new mongoose.Schema({
  account: { type: mongoose.Schema.Types.ObjectId, ref: "AccountingAccount", required: true },
  debitKobo: { type: Number, required: true, min: 0, default: 0 },
  creditKobo: { type: Number, required: true, min: 0, default: 0 },
  description: { type: String, default: "", trim: true },
  division: { type: String, default: "", trim: true },
  projectReference: { type: String, default: "", trim: true },
}, { _id: false });

const accountingJournalSchema = new mongoose.Schema({
  reference: { type: String, required: true, unique: true },
  date: { type: Date, required: true },
  description: { type: String, required: true, trim: true },
  documentReference: { type: String, default: "", trim: true },
  status: { type: String, enum: ["draft", "posted"], default: "draft" },
  lines: { type: [journalLineSchema], required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  postedAt: { type: Date, default: null },
  reversalOf: { type: mongoose.Schema.Types.ObjectId, ref: "AccountingJournal", default: null },
}, { timestamps: true });

accountingJournalSchema.index({ date: 1, status: 1 });
accountingJournalSchema.index({ reversalOf: 1 }, { unique: true, partialFilterExpression: { reversalOf: { $type: "objectId" } } });
export default mongoose.model("AccountingJournal", accountingJournalSchema);
