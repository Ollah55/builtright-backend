import test from "node:test";
import assert from "node:assert/strict";
import {
  installationSchedulingGate,
  installationTransition,
} from "./installationWorkflow.js";

test("installation remains locked before the bank disbursement is confirmed", () => {
  assert.deepEqual(
    installationSchedulingGate({ assignmentStatus: "completed", projectStatus: "quotation-approved", bankStatus: "manual-application-ready" }),
    { allowed: false, reason: "disbursement-unconfirmed" },
  );
});

test("completed assessment and confirmed disbursement unlock installation scheduling", () => {
  assert.deepEqual(
    installationSchedulingGate({ assignmentStatus: "completed", projectStatus: "disbursed", bankStatus: "disbursed" }),
    { allowed: true, reason: "funding-confirmed" },
  );
});

test("installation progress follows schedule, work, testing and completion in order", () => {
  assert.equal(installationTransition("in-progress").from, "scheduled");
  assert.equal(installationTransition("testing-commissioning").from, "in-progress");
  assert.equal(installationTransition("completed").from, "testing-commissioning");
  assert.equal(installationTransition("unsupported"), null);
});
