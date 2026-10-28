import assert from "node:assert/strict";
import test from "node:test";

import {
  assessmentPaymentState,
  initialAssessmentInspection,
} from "./assessmentPayment.js";

test("confirmed WhatsApp payment remains confirmed through scheduling", () => {
  assert.deepEqual(assessmentPaymentState("payment-confirmed"), {
    confirmed: true,
    scheduledFeeStatus: "payment-confirmed",
  });
});

test("unconfirmed payment never becomes confirmed through scheduling", () => {
  assert.deepEqual(assessmentPaymentState("not-requested"), {
    confirmed: false,
    scheduledFeeStatus: "not-requested",
  });
});

test("sales can record paid assessment before installer scheduling", () => {
  const now = new Date("2026-10-28T10:00:00.000Z");
  assert.deepEqual(initialAssessmentInspection({
    feeAmount: 25000,
    paymentConfirmed: true,
    completed: false,
    now,
  }), {
    feeAmount: 25000,
    feeStatus: "payment-confirmed",
    status: "not-scheduled",
    paymentConfirmedAt: now,
  });
});
