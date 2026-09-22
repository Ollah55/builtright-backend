import test from "node:test";
import assert from "node:assert/strict";
import { parseNairaToKobo, validateJournalLines, trialBalance, profitAndLoss, balanceSheet, generalLedger } from "./accountingMath.js";
import { ACCOUNTING_START_DATE } from "./settings.js";

const accounts = [
  { _id: "bank", code: "1000", name: "Bank", type: "asset", normalSide: "debit" },
  { _id: "equipment", code: "1500", name: "Office equipment", type: "asset", normalSide: "debit" },
  { _id: "depreciation", code: "1590", name: "Accumulated depreciation", type: "asset", normalSide: "credit" },
  { _id: "loan", code: "2000", name: "Loan payable", type: "liability", normalSide: "credit" },
  { _id: "capital", code: "3000", name: "Owner capital", type: "equity", normalSide: "credit" },
  { _id: "revenue", code: "4000", name: "Service revenue", type: "revenue", normalSide: "credit" },
  { _id: "expense", code: "5000", name: "Office expenses", type: "expense", normalSide: "debit" },
];

const journal = (date, reference, lines) => ({ date, reference, status: "posted", description: reference, lines: lines.map(([account, debitKobo, creditKobo]) => ({ account, debitKobo, creditKobo })) });
const journals = [
  journal("2026-01-01", "capital", [["bank", 1000000, 0], ["capital", 0, 1000000]]),
  journal("2026-01-02", "loan", [["bank", 500000, 0], ["loan", 0, 500000]]),
  journal("2026-01-03", "equipment", [["equipment", 300000, 0], ["bank", 0, 300000]]),
  journal("2026-01-04", "revenue", [["bank", 200000, 0], ["revenue", 0, 200000]]),
  journal("2026-01-05", "expense", [["expense", 50000, 0], ["bank", 0, 50000]]),
  journal("2026-01-06", "depreciation", [["expense", 10000, 0], ["depreciation", 0, 10000]]),
  { ...journal("2026-01-07", "draft", [["bank", 999999, 0], ["revenue", 0, 999999]]), status: "draft" },
];

test("currency parsing is exact to kobo and rejects fractional kobo", () => {
  assert.equal(parseNairaToKobo("94065.45"), 9406545);
  assert.equal(parseNairaToKobo("0.5"), 50);
  assert.throws(() => parseNairaToKobo("1.001"));
  assert.throws(() => parseNairaToKobo("-1"));
});

test("journals must have matching debits and credits", () => {
  assert.deepEqual(validateJournalLines([{ account: "bank", debitKobo: 100, creditKobo: 0 }, { account: "capital", debitKobo: 0, creditKobo: 100 }]), { debits: 100, credits: 100 });
  assert.throws(() => validateJournalLines([{ account: "bank", debitKobo: 100, creditKobo: 0 }, { account: "capital", debitKobo: 0, creditKobo: 99 }]));
  assert.throws(() => validateJournalLines([{ account: "bank", debitKobo: 100, creditKobo: 100 }, { account: "capital", debitKobo: 0, creditKobo: 100 }]));
});

test("posted history produces balanced trial balance and statements", () => {
  const tb = trialBalance(accounts, journals);
  assert.equal(tb.balanced, true);
  assert.equal(tb.totalDebitKobo, 1710000);
  const pnl = profitAndLoss(accounts, journals);
  assert.equal(pnl.totalRevenueKobo, 200000);
  assert.equal(pnl.totalExpenseKobo, 60000);
  assert.equal(pnl.netProfitKobo, 140000);
  const sheet = balanceSheet(accounts, journals);
  assert.equal(sheet.totalAssetsKobo, 1640000);
  assert.equal(sheet.totalLiabilitiesKobo, 500000);
  assert.equal(sheet.totalEquityKobo, 1140000);
  assert.equal(sheet.differenceKobo, 0);
  assert.equal(sheet.assets.find((row) => row.code === "1590").amountKobo, -10000);
});

test("ledger carries forward opening balance and date filters", () => {
  const result = generalLedger(accounts[0], journals, "2026-01-04", "2026-01-05");
  assert.equal(result.openingKobo, 1200000);
  assert.equal(result.rows.length, 2);
  assert.equal(result.closingKobo, 1350000);
  assert.equal(profitAndLoss(accounts, journals, "2026-01-04", "2026-01-05").netProfitKobo, 150000);
});

test("September reporting start does not invent or erase earlier history", () => {
  assert.equal(ACCOUNTING_START_DATE, "2026-09-01");
  const history = [
    journal("2026-08-31", "earlier-service", [["bank", 10000, 0], ["revenue", 0, 10000]]),
    journal("2026-09-01", "september-service", [["bank", 20000, 0], ["revenue", 0, 20000]]),
  ];
  assert.equal(profitAndLoss(accounts, history, ACCOUNTING_START_DATE).totalRevenueKobo, 20000);
  assert.equal(balanceSheet(accounts, history).totalAssetsKobo, 30000);
});
