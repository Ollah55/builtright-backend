import express from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import User from "../models/User.js";
import AccountingAccount from "../models/AccountingAccount.js";
import AccountingAsset from "../models/AccountingAsset.js";
import AccountingJournal from "../models/AccountingJournal.js";
import sendEmail from "../utils/sendEmail.js";
import { accountBalances, balanceSheet, generalLedger, normalSideForType, parseNairaToKobo, profitAndLoss, trialBalance, validateJournalLines } from "./accountingMath.js";
import { ACCOUNTING_START_DATE } from "./settings.js";

const router = express.Router();
const allowedTypes = new Set(["asset", "liability", "equity", "revenue", "expense"]);
const validDay = (value) => typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00.000Z`)) && new Date(`${value}T00:00:00.000Z`).toISOString().startsWith(value);
const dateAt = (day) => new Date(`${day}T12:00:00.000Z`);
const tokenHash = (raw) => crypto.createHash("sha256").update(raw).digest("hex");
const clean = (value, max = 200) => String(value || "").trim().slice(0, max);
const nullableDay = (value) => {
  if (value === null || value === undefined || value === "") return null;
  if (!validDay(value)) throw new Error("Enter a valid acquisition date.");
  return dateAt(value);
};
const optionalInteger = (value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) => {
  if (value === null || value === undefined || value === "") return null;
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) throw new Error(`${label} is invalid.`);
  return result;
};
const userView = (user) => ({ id: user._id, fullName: user.fullName, email: user.email, isActive: user.isActive, invitedAt: user.accountantProfile?.invitedAt, invitationExpiresAt: user.accountantProfile?.invitationExpiresAt, activatedAt: user.accountantProfile?.activatedAt });

export function accountingRoutes(requireAdminAuth) {
  const accountantAuth = async (req, res, next) => {
    try {
      const bearer = req.get("authorization") || "";
      if (!bearer.startsWith("Bearer ")) return res.status(401).json({ status: false, message: "Accountant sign-in required." });
      const claims = jwt.verify(bearer.slice(7), process.env.JWT_SECRET);
      if (claims.role !== "accountant" || !mongoose.isValidObjectId(claims.id)) return res.status(403).json({ status: false, message: "Accountant access required." });
      const user = await User.findOne({ _id: claims.id, role: "accountant", isActive: true });
      if (!user) return res.status(403).json({ status: false, message: "Accountant access is inactive." });
      req.accountant = user;
      next();
    } catch {
      return res.status(401).json({ status: false, message: "Invalid or expired accountant session." });
    }
  };

  router.get("/admin/accountant", requireAdminAuth, async (_req, res) => {
    try {
      const users = await User.find({ role: "accountant" }).sort({ createdAt: -1 }).select("fullName email isActive accountantProfile.invitedAt accountantProfile.invitationExpiresAt accountantProfile.activatedAt").lean();
      res.json({ status: true, startDate: ACCOUNTING_START_DATE, accountants: users.map(userView) });
    } catch { res.status(500).json({ status: false, message: "Could not load accountant access." }); }
  });

  router.post("/admin/accountant/invite", requireAdminAuth, async (req, res) => {
    try {
      const fullName = clean(req.body.fullName, 120);
      const email = clean(req.body.email, 200).toLowerCase();
      if (!fullName || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ status: false, message: "Enter the accountant's name and a valid email." });
      const active = await User.findOne({ role: "accountant", isActive: true });
      if (active) return res.status(409).json({ status: false, message: "An accountant is already active. Revoke access before inviting a replacement." });
      const otherPending = await User.findOne({ role: "accountant", isActive: false, email: { $ne: email }, "accountantProfile.invitationExpiresAt": { $gt: new Date() } });
      if (otherPending) return res.status(409).json({ status: false, message: "A different accountant invitation is pending. Revoke it before inviting another person." });
      let user = await User.findOne({ email });
      if (user && user.role !== "accountant") return res.status(409).json({ status: false, message: "That email belongs to another portal role." });
      const raw = crypto.randomBytes(32).toString("hex");
      if (!user) user = new User({ fullName, email, phone: "", password: await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 10), role: "accountant", isActive: false });
      user.fullName = fullName;
      user.isActive = false;
      user.accountantProfile = { invitationTokenHash: tokenHash(raw), invitationExpiresAt: new Date(Date.now() + 7 * 86400000), invitedAt: new Date(), activatedAt: null };
      await user.save();
      const link = `${process.env.FRONTEND_URL || "https://www.builtrightltd.com"}/accounting/activate?token=${raw}`;
      await sendEmail({ to: email, subject: "Activate your BuiltRight accountant account", html: `<h2>BuiltRight Accounting</h2><p>Hello ${fullName.replace(/[&<>"']/g, "")},</p><p>You have been invited to manage BuiltRight's accounting records. <a href="${link}">Set your password</a> within 7 days.</p>` });
      res.status(201).json({ status: true, message: "Accountant invitation sent.", accountant: userView(user) });
    } catch (error) {
      console.error("ACCOUNTANT INVITE ERROR:", error);
      res.status(500).json({ status: false, message: "Could not send the accountant invitation. You can retry with the same email." });
    }
  });

  router.patch("/admin/accountant/:id/revoke", requireAdminAuth, async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ status: false, message: "Invalid accountant ID." });
      const user = await User.findOne({ _id: req.params.id, role: "accountant" });
      if (!user) return res.status(404).json({ status: false, message: "Accountant not found." });
      user.isActive = false;
      user.accountantProfile.invitationTokenHash = "";
      user.accountantProfile.invitationExpiresAt = null;
      await user.save();
      res.json({ status: true, message: "Accountant access revoked. Historical journal attribution is retained." });
    } catch { res.status(500).json({ status: false, message: "Could not revoke access." }); }
  });

  router.post("/accounting/activate", async (req, res) => {
    try {
      const raw = clean(req.body.token, 128);
      const password = String(req.body.password || "");
      if (!/^[a-f0-9]{64}$/.test(raw) || password.length < 12) return res.status(400).json({ status: false, message: "Use a valid invitation and a password of at least 12 characters." });
      const user = await User.findOne({ role: "accountant", isActive: false, "accountantProfile.invitationTokenHash": tokenHash(raw), "accountantProfile.invitationExpiresAt": { $gt: new Date() } });
      if (!user) return res.status(400).json({ status: false, message: "This invitation is invalid or expired." });
      user.password = await bcrypt.hash(password, 12);
      user.isActive = true;
      user.accountantProfile.invitationTokenHash = "";
      user.accountantProfile.invitationExpiresAt = null;
      user.accountantProfile.activatedAt = new Date();
      await user.save();
      res.json({ status: true, message: "Accountant account activated. You can now sign in." });
    } catch { res.status(500).json({ status: false, message: "Could not activate accountant account." }); }
  });

  router.post("/accounting/login", async (req, res) => {
    try {
      const user = await User.findOne({ email: clean(req.body.email).toLowerCase(), role: "accountant", isActive: true });
      if (!user || !(await bcrypt.compare(String(req.body.password || ""), user.password))) return res.status(401).json({ status: false, message: "Invalid accountant credentials." });
      const token = jwt.sign({ id: user._id, email: user.email, role: "accountant" }, process.env.JWT_SECRET, { expiresIn: "7d" });
      res.json({ status: true, token, user: userView(user) });
    } catch { res.status(500).json({ status: false, message: "Could not sign in." }); }
  });

  router.get("/accounting/me", accountantAuth, (req, res) => res.json({ status: true, user: userView(req.accountant), startDate: ACCOUNTING_START_DATE }));

  router.get("/accounting/accounts", accountantAuth, async (_req, res) => {
    try { res.json({ status: true, accounts: await AccountingAccount.find().sort({ code: 1 }).lean() }); }
    catch { res.status(500).json({ status: false, message: "Could not load chart of accounts." }); }
  });

  router.post("/accounting/accounts", accountantAuth, async (req, res) => {
    try {
      const code = clean(req.body.code, 20).toUpperCase();
      const name = clean(req.body.name, 120);
      const type = clean(req.body.type, 20);
      const normalSide = clean(req.body.normalSide, 10) || normalSideForType(type);
      if (!/^[A-Z0-9-]{2,20}$/.test(code) || !name || !allowedTypes.has(type) || !["debit", "credit"].includes(normalSide)) return res.status(400).json({ status: false, message: "Enter a valid code, name, type and normal side." });
      const account = await AccountingAccount.create({ code, name, type, normalSide, description: clean(req.body.description, 300) });
      res.status(201).json({ status: true, account });
    } catch (error) { res.status(error.code === 11000 ? 409 : 500).json({ status: false, message: error.code === 11000 ? "That account code already exists." : "Could not add account." }); }
  });

  router.patch("/accounting/accounts/:id", accountantAuth, async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ status: false, message: "Invalid account ID." });
      const account = await AccountingAccount.findById(req.params.id);
      if (!account) return res.status(404).json({ status: false, message: "Account not found." });
      if (req.body.name !== undefined) account.name = clean(req.body.name, 120);
      if (req.body.description !== undefined) account.description = clean(req.body.description, 300);
      if (req.body.isActive !== undefined) account.isActive = req.body.isActive === true;
      if (!account.name) return res.status(400).json({ status: false, message: "Account name is required." });
      await account.save();
      res.json({ status: true, account });
    } catch { res.status(500).json({ status: false, message: "Could not update account." }); }
  });

  router.get("/accounting/assets", accountantAuth, async (_req, res) => {
    try {
      const assets = await AccountingAsset.find().sort({ assetCode: 1 }).lean();
      res.json({ status: true, assets });
    } catch {
      res.status(500).json({ status: false, message: "Could not load the fixed-asset register." });
    }
  });

  const applyAssetInput = (asset, body, { creating = false } = {}) => {
    if (creating || body.assetCode !== undefined) {
      const assetCode = clean(body.assetCode, 30).toUpperCase();
      if (!/^[A-Z0-9-]{2,30}$/.test(assetCode)) throw new Error("Enter a valid asset code.");
      asset.assetCode = assetCode;
    }
    if (creating || body.name !== undefined) asset.name = clean(body.name, 160);
    if (creating || body.acquisitionDate !== undefined) asset.acquisitionDate = nullableDay(body.acquisitionDate);
    if (creating || body.cost !== undefined) asset.costKobo = parseNairaToKobo(body.cost);
    if (body.category !== undefined) asset.category = clean(body.category, 100) || "Unassigned";
    if (body.location !== undefined) asset.location = clean(body.location, 160);
    if (body.condition !== undefined) asset.condition = clean(body.condition, 100);
    if (body.usefulLifeMonths !== undefined) asset.usefulLifeMonths = optionalInteger(body.usefulLifeMonths, "Useful life", 1, 600);
    if (body.residualValue !== undefined) asset.residualValueKobo = parseNairaToKobo(body.residualValue || "0");
    if (body.openingAccumulatedDepreciation !== undefined) asset.openingAccumulatedDepreciationKobo = parseNairaToKobo(body.openingAccumulatedDepreciation || "0");
    if (body.status !== undefined) {
      const status = clean(body.status, 30);
      if (!["review-required", "active", "disposed"].includes(status)) throw new Error("Choose a valid asset status.");
      asset.status = status;
    }
    if (body.notes !== undefined) asset.notes = clean(body.notes, 500);
    if (!asset.name) throw new Error("Asset name is required.");
    if (!Number.isSafeInteger(asset.costKobo) || asset.costKobo <= 0) throw new Error("Asset cost must be greater than zero.");
    if (asset.residualValueKobo > asset.costKobo) throw new Error("Residual value cannot exceed asset cost.");
    if (asset.openingAccumulatedDepreciationKobo > asset.costKobo - asset.residualValueKobo) throw new Error("Accumulated depreciation cannot exceed the depreciable amount.");
    if (asset.status === "active" && (!asset.acquisitionDate || !asset.usefulLifeMonths || asset.category === "Unassigned")) throw new Error("Complete the acquisition date, category and useful life before marking an asset active.");
  };

  router.post("/accounting/assets", accountantAuth, async (req, res) => {
    try {
      const asset = new AccountingAsset({ createdBy: req.accountant._id, updatedBy: req.accountant._id });
      applyAssetInput(asset, req.body, { creating: true });
      await asset.save();
      res.status(201).json({ status: true, asset });
    } catch (error) {
      res.status(error.code === 11000 ? 409 : 400).json({ status: false, message: error.code === 11000 ? "That asset code already exists." : error.message || "Could not add the asset." });
    }
  });

  router.patch("/accounting/assets/:id", accountantAuth, async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ status: false, message: "Invalid asset ID." });
      const asset = await AccountingAsset.findById(req.params.id);
      if (!asset) return res.status(404).json({ status: false, message: "Asset not found." });
      applyAssetInput(asset, req.body);
      asset.updatedBy = req.accountant._id;
      await asset.save();
      res.json({ status: true, asset });
    } catch (error) {
      res.status(error.code === 11000 ? 409 : 400).json({ status: false, message: error.code === 11000 ? "That asset code already exists." : error.message || "Could not update the asset." });
    }
  });

  router.delete("/accounting/assets/:id", accountantAuth, async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ status: false, message: "Invalid asset ID." });
      const deleted = await AccountingAsset.findOneAndDelete({ _id: req.params.id, status: "review-required" });
      if (!deleted) return res.status(404).json({ status: false, message: "Only assets awaiting review can be deleted." });
      res.json({ status: true, message: "Asset removed from the register." });
    } catch {
      res.status(500).json({ status: false, message: "Could not delete the asset." });
    }
  });

  const normalizeJournal = async (body) => {
    const description = clean(body.description, 300);
    if (!validDay(body.date) || !description) throw new Error("Enter a valid journal date and description.");
    if (!Array.isArray(body.lines) || body.lines.length > 100) throw new Error("A journal needs 2–100 lines.");
    const lines = body.lines.map((line) => ({ account: line.account, debitKobo: parseNairaToKobo(line.debit || "0"), creditKobo: parseNairaToKobo(line.credit || "0"), description: clean(line.description, 200), division: clean(line.division, 80), projectReference: clean(line.projectReference, 80) }));
    validateJournalLines(lines);
    if (lines.some((line) => !mongoose.isValidObjectId(line.account))) throw new Error("Select a valid account for every line.");
    const accounts = await AccountingAccount.find({ _id: { $in: lines.map((line) => line.account) }, isActive: true }).select("_id").lean();
    if (accounts.length !== new Set(lines.map((line) => String(line.account))).size) throw new Error("Every journal line must use an active account.");
    return { date: dateAt(body.date), description, documentReference: clean(body.documentReference, 100), lines };
  };

  router.get("/accounting/journals", accountantAuth, async (req, res) => {
    try {
      const status = req.query.status;
      const match = ["draft", "posted"].includes(status) ? { status } : {};
      const journals = await AccountingJournal.find(match).sort({ date: -1, createdAt: -1 }).limit(500).populate("lines.account", "code name type normalSide").lean();
      res.json({ status: true, journals });
    } catch { res.status(500).json({ status: false, message: "Could not load journals." }); }
  });

  router.post("/accounting/journals", accountantAuth, async (req, res) => {
    try {
      const data = await normalizeJournal(req.body);
      const reference = `BRJ-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
      const journal = await AccountingJournal.create({ ...data, reference, createdBy: req.accountant._id });
      res.status(201).json({ status: true, journal });
    } catch (error) { res.status(400).json({ status: false, message: error.message || "Could not save draft." }); }
  });

  router.patch("/accounting/journals/:id", accountantAuth, async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ status: false, message: "Invalid journal ID." });
      const normalized = await normalizeJournal(req.body);
      const journal = await AccountingJournal.findOneAndUpdate(
        { _id: req.params.id, status: "draft" },
        { $set: normalized },
        { new: true, runValidators: true },
      );
      if (!journal) return res.status(404).json({ status: false, message: "Only draft journals can be edited." });
      res.json({ status: true, journal });
    } catch (error) { res.status(400).json({ status: false, message: error.message || "Could not update draft." }); }
  });

  router.delete("/accounting/journals/:id", accountantAuth, async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ status: false, message: "Invalid journal ID." });
      const deleted = await AccountingJournal.findOneAndDelete({ _id: req.params.id, status: "draft" });
      if (!deleted) return res.status(404).json({ status: false, message: "Only draft journals can be deleted." });
      res.json({ status: true, message: "Draft deleted." });
    } catch { res.status(500).json({ status: false, message: "Could not delete draft." }); }
  });

  router.post("/accounting/journals/:id/post", accountantAuth, async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ status: false, message: "Invalid journal ID." });
      const draft = await AccountingJournal.findOne({ _id: req.params.id, status: "draft" });
      if (!draft) return res.status(404).json({ status: false, message: "Draft not found or already posted." });
      validateJournalLines(draft.lines);
      const activeCount = await AccountingAccount.countDocuments({ _id: { $in: draft.lines.map((line) => line.account) }, isActive: true });
      if (activeCount !== new Set(draft.lines.map((line) => String(line.account))).size) return res.status(400).json({ status: false, message: "A journal account is now inactive. Reactivate it before posting." });
      const posted = await AccountingJournal.findOneAndUpdate({ _id: draft._id, status: "draft" }, { $set: { status: "posted", postedBy: req.accountant._id, postedAt: new Date() } }, { new: true });
      if (!posted) return res.status(409).json({ status: false, message: "This journal has already been posted." });
      res.json({ status: true, journal: posted });
    } catch (error) { res.status(400).json({ status: false, message: error.message || "Could not post journal." }); }
  });

  router.post("/accounting/journals/:id/reverse", accountantAuth, async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ status: false, message: "Invalid journal ID." });
      const source = await AccountingJournal.findOne({ _id: req.params.id, status: "posted" });
      if (!source) return res.status(404).json({ status: false, message: "Posted journal not found." });
      if (await AccountingJournal.exists({ reversalOf: source._id })) return res.status(409).json({ status: false, message: "This journal already has a reversal." });
      const day = clean(req.body.date, 10);
      if (!validDay(day)) return res.status(400).json({ status: false, message: "Choose a valid reversal date." });
      const reversal = await AccountingJournal.create({ reference: `BRJ-REV-${crypto.randomBytes(7).toString("hex").toUpperCase()}`, date: dateAt(day), description: `Reversal of ${source.reference}: ${source.description}`, documentReference: source.documentReference, status: "posted", lines: source.lines.map((line) => ({ account: line.account, debitKobo: line.creditKobo, creditKobo: line.debitKobo, description: line.description, division: line.division, projectReference: line.projectReference })), createdBy: req.accountant._id, postedBy: req.accountant._id, postedAt: new Date(), reversalOf: source._id });
      res.status(201).json({ status: true, journal: reversal });
    } catch { res.status(500).json({ status: false, message: "Could not reverse journal." }); }
  });

  const book = async () => {
    const [accounts, journals] = await Promise.all([AccountingAccount.find().sort({ code: 1 }).lean(), AccountingJournal.find({ status: "posted" }).select("date status reference description documentReference lines").lean()]);
    return { accounts, journals };
  };

  router.get("/accounting/ledger/:accountId", accountantAuth, async (req, res) => {
    try {
      const { from, to } = req.query;
      if ((from && !validDay(from)) || (to && !validDay(to)) || (from && to && from > to)) return res.status(400).json({ status: false, message: "Invalid date range." });
      const { accounts, journals } = await book();
      const account = accounts.find((item) => String(item._id) === req.params.accountId);
      if (!account) return res.status(404).json({ status: false, message: "Account not found." });
      res.json({ status: true, account, ...generalLedger(account, journals, from, to) });
    } catch { res.status(500).json({ status: false, message: "Could not load ledger." }); }
  });

  router.get("/accounting/reports", accountantAuth, async (req, res) => {
    try {
      const { from, to, asOf } = req.query;
      if ([from, to, asOf].some((date) => date && !validDay(date)) || (from && to && from > to)) return res.status(400).json({ status: false, message: "Invalid report date range." });
      const { accounts, journals } = await book();
      const profitLossFrom = from || ACCOUNTING_START_DATE;
      res.json({ status: true, startDate: ACCOUNTING_START_DATE, asOf: asOf || null, from: profitLossFrom, to: to || null, trialBalance: trialBalance(accounts, journals, asOf), profitAndLoss: profitAndLoss(accounts, journals, profitLossFrom, to), balanceSheet: balanceSheet(accounts, journals, asOf), accountBalances: accountBalances(accounts, journals, null, asOf).map((row) => ({ code: row.account.code, name: row.account.name, type: row.account.type, balanceKobo: row.normalBalanceKobo })) });
    } catch (error) { console.error("ACCOUNTING REPORT ERROR:", error); res.status(500).json({ status: false, message: "Could not prepare reports." }); }
  });

  return router;
}
