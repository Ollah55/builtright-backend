import assert from "node:assert/strict";
import test from "node:test";
import {
  assignmentRevision,
  assignmentRevisionFilter,
  installerAssignmentWriteFilter,
} from "./assignmentConcurrency.js";

test("assignment revision normalizes legacy and current values", () => {
  assert.equal(assignmentRevision(undefined), 0);
  assert.equal(assignmentRevision("4"), 4);
  assert.equal(assignmentRevision(-1), 0);
});
test("legacy assignments can be claimed once with a zero-or-missing revision filter", () => {
  assert.deepEqual(assignmentRevisionFilter(0), {
    $or: [
      { "installerAssignment.revision": 0 },
      { "installerAssignment.revision": { $exists: false } },
    ],
  });
});

test("installer writes bind project, authenticated owner, status and revision", () => {
  assert.deepEqual(
    installerAssignmentWriteFilter({
      projectId: "project-1",
      installerId: "installer-1",
      revision: 7,
      statuses: ["accepted", "scheduled"],
    }),
    {
      _id: "project-1",
      "installerAssignment.installer": "installer-1",
      "installerAssignment.status": { $in: ["accepted", "scheduled"] },
      "installerAssignment.revision": 7,
    },
  );
});

