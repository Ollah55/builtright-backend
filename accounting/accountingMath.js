export const normalSideForType = (type) => ["asset", "expense"].includes(type) ? "debit" : "credit";

export function parseNairaToKobo(value) {
  const text = String(value ?? "").trim();
  if (!/^(?:0|[1-9]\d*)(?:\.\d{1,2})?$/.test(text)) throw new Error("Enter a non-negative amount with at most two decimal places.");
  const [naira, fraction = ""] = text.split(".");
  const result = Number(naira) * 100 + Number(fraction.padEnd(2, "0"));
  if (!Number.isSafeInteger(result)) throw new Error("Amount exceeds the supported range.");
  return result;
}

export function validateJournalLines(lines) {
  if (!Array.isArray(lines) || lines.length < 2) throw new Error("A journal needs at least two lines.");
  let debits = 0;
  let credits = 0;
  for (const line of lines) {
    if (!Number.isSafeInteger(line.debitKobo) || !Number.isSafeInteger(line.creditKobo) || line.debitKobo < 0 || line.creditKobo < 0) {
      throw new Error("Journal amounts must be valid non-negative amounts.");
    }
    if ((line.debitKobo > 0) === (line.creditKobo > 0)) throw new Error("Each line must have either a debit or a credit, not both or neither.");
    debits += line.debitKobo;
    credits += line.creditKobo;
  }
  if (!Number.isSafeInteger(debits) || !Number.isSafeInteger(credits) || debits !== credits) throw new Error("Total debits must equal total credits.");
  if (new Set(lines.map((line) => String(line.account))).size < 2) throw new Error("Use at least two different accounts.");
  return { debits, credits };
}

export function accountBalances(accounts, journals, fromDate = null, toDate = null) {
  const result = new Map(accounts.map((account) => [String(account._id), { account, debitKobo: 0, creditKobo: 0 }]));
  const from = fromDate ? Date.parse(`${fromDate}T00:00:00.000Z`) : -Infinity;
  const to = toDate ? Date.parse(`${toDate}T23:59:59.999Z`) : Infinity;
  for (const journal of journals) {
    if (journal.status !== "posted") continue;
    const day = new Date(journal.date).getTime();
    if (day < from || day > to) continue;
    for (const line of journal.lines) {
      const balance = result.get(String(line.account?._id || line.account));
      if (!balance) continue;
      balance.debitKobo += line.debitKobo;
      balance.creditKobo += line.creditKobo;
    }
  }
  return [...result.values()].map((row) => ({
    ...row,
    netDebitKobo: row.debitKobo - row.creditKobo,
    normalBalanceKobo: row.account.normalSide === "debit" ? row.debitKobo - row.creditKobo : row.creditKobo - row.debitKobo,
  }));
}

export function trialBalance(accounts, journals, asOf = null) {
  const rows = accountBalances(accounts, journals, null, asOf).map((row) => ({
    code: row.account.code,
    name: row.account.name,
    type: row.account.type,
    debitKobo: Math.max(row.netDebitKobo, 0),
    creditKobo: Math.max(-row.netDebitKobo, 0),
  })).filter((row) => row.debitKobo || row.creditKobo);
  const totalDebitKobo = rows.reduce((sum, row) => sum + row.debitKobo, 0);
  const totalCreditKobo = rows.reduce((sum, row) => sum + row.creditKobo, 0);
  return { rows, totalDebitKobo, totalCreditKobo, balanced: totalDebitKobo === totalCreditKobo };
}

export function profitAndLoss(accounts, journals, fromDate = null, toDate = null) {
  const balances = accountBalances(accounts, journals, fromDate, toDate);
  const revenue = balances.filter((row) => row.account.type === "revenue").map((row) => ({ code: row.account.code, name: row.account.name, amountKobo: row.creditKobo - row.debitKobo }));
  const expenses = balances.filter((row) => row.account.type === "expense").map((row) => ({ code: row.account.code, name: row.account.name, amountKobo: row.debitKobo - row.creditKobo }));
  const totalRevenueKobo = revenue.reduce((sum, row) => sum + row.amountKobo, 0);
  const totalExpenseKobo = expenses.reduce((sum, row) => sum + row.amountKobo, 0);
  return { revenue, expenses, totalRevenueKobo, totalExpenseKobo, netProfitKobo: totalRevenueKobo - totalExpenseKobo };
}

export function balanceSheet(accounts, journals, asOf = null) {
  const balances = accountBalances(accounts, journals, null, asOf);
  const group = (type) => balances.filter((row) => row.account.type === type).map((row) => ({
    code: row.account.code, name: row.account.name,
    amountKobo: type === "asset" ? row.netDebitKobo : -row.netDebitKobo,
  }));
  const assets = group("asset");
  const liabilities = group("liability");
  const equity = group("equity");
  const retainedEarningsKobo = profitAndLoss(accounts, journals, null, asOf).netProfitKobo;
  const totalAssetsKobo = assets.reduce((sum, row) => sum + row.amountKobo, 0);
  const totalLiabilitiesKobo = liabilities.reduce((sum, row) => sum + row.amountKobo, 0);
  const totalEquityKobo = equity.reduce((sum, row) => sum + row.amountKobo, 0) + retainedEarningsKobo;
  return { assets, liabilities, equity, retainedEarningsKobo, totalAssetsKobo, totalLiabilitiesKobo, totalEquityKobo, differenceKobo: totalAssetsKobo - totalLiabilitiesKobo - totalEquityKobo };
}

export function generalLedger(account, journals, fromDate = null, toDate = null) {
  const accountId = String(account._id);
  const start = fromDate ? Date.parse(`${fromDate}T00:00:00.000Z`) : -Infinity;
  const end = toDate ? Date.parse(`${toDate}T23:59:59.999Z`) : Infinity;
  let openingKobo = 0;
  const rows = [];
  const sorted = journals.filter((journal) => journal.status === "posted")
    .sort((a, b) => new Date(a.date) - new Date(b.date) || String(a.reference).localeCompare(String(b.reference)));
  for (const journal of sorted) {
    const timestamp = new Date(journal.date).getTime();
    if (timestamp > end) continue;
    for (const line of journal.lines) {
      if (String(line.account?._id || line.account) !== accountId) continue;
      const delta = account.normalSide === "debit" ? line.debitKobo - line.creditKobo : line.creditKobo - line.debitKobo;
      if (timestamp < start) openingKobo += delta;
      else rows.push({ date: journal.date, reference: journal.reference, description: line.description || journal.description, documentReference: journal.documentReference, debitKobo: line.debitKobo, creditKobo: line.creditKobo, deltaKobo: delta });
    }
  }
  let runningKobo = openingKobo;
  return { openingKobo, rows: rows.map((row) => ({ ...row, balanceKobo: (runningKobo += row.deltaKobo) })), closingKobo: runningKobo };
}
