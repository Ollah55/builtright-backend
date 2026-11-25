import assert from "node:assert/strict";
import test from "node:test";
import { resolveMaintenanceTechnician } from "./maintenanceTechnician.js";

const id = "507f1f77bcf86cd799439011";

test("assigns only an active installer by account ID", async () => {
  const result = await resolveMaintenanceTechnician(id, async (filter) => {
    assert.deepEqual(filter, { _id: id, role: "installer", isActive: true });
    return { _id: id };
  });
  assert.equal(result, id);
});

test("unassigns explicitly without looking up another account", async () => {
  assert.equal(await resolveMaintenanceTechnician(null, assert.fail), null);
});

test("rejects malformed IDs and accounts that are not active installers", async () => {
  for (const invalid of [undefined, "", "not-an-id", { $ne: null }]) {
    await assert.rejects(resolveMaintenanceTechnician(invalid, assert.fail), { statusCode: 400 });
  }
  await assert.rejects(resolveMaintenanceTechnician(id, async () => null), { statusCode: 400 });
});
