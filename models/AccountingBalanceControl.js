import mongoose from "mongoose";

const accountingBalanceControlSchema = new mongoose.Schema(
  {
    account: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "AccountingAccount",
      required: true,
      unique: true,
    },
    openingBalanceKobo: { type: Number, default: null, min: 0 },
    offsetAccount: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "AccountingAccount",
      default: null,
    },
    openingJournal: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "AccountingJournal",
      default: null,
    },
    actualClosingBalanceKobo: { type: Number, default: null, min: 0 },
    actualClosingAsOf: { type: Date, default: null },
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true },
);

export default mongoose.model(
  "AccountingBalanceControl",
  accountingBalanceControlSchema,
);
