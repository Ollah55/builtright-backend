import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  ASHGRIDX_EVENTS,
  ashGridEventSemantics,
  getAshGridXConfig,
  normalizeAshGridEvent,
  parseAshGridTimestamp,
  verifyAshGridWebhook,
} from "./ashgridx.js";

test("the confirmed AshGridX event catalogue is explicit", () => {
  assert.deepEqual(ASHGRIDX_EVENTS, ["DEVICE_ONLINE", "DEVICE_OFFLINE", "BYPASS", "BYPASS_REVERSED"]);
});

test("BYPASS and BYPASS_REVERSED update protection without claiming inverter shutdown", () => {
  const bypass = ashGridEventSemantics("BYPASS");
  const reversed = ashGridEventSemantics("BYPASS_REVERSED");
  assert.equal(bypass.protectionState, "bypass");
  assert.equal(bypass.tamperState, "confirmed");
  assert.equal(reversed.protectionState, "normal");
  assert.equal(reversed.tamperState, "clear");
  assert.equal("inverterState" in bypass, false);
});

test("event normalization accepts the documented data envelope", () => {
  assert.deepEqual(normalizeAshGridEvent({ event: "DEVICE_ONLINE", data: { customerDeviceId: "AGX-001" } }), {
    eventName: "DEVICE_ONLINE",
    data: { customerDeviceId: "AGX-001" },
    deviceIdentifier: "AGX-001",
  });
});

test("timestamps accept seconds, milliseconds and ISO values", () => {
  const now = Date.parse("2026-10-27T10:00:00.000Z");
  assert.equal(parseAshGridTimestamp(now / 1000, now).getTime(), now);
  assert.equal(parseAshGridTimestamp(now, now).getTime(), now);
  assert.equal(parseAshGridTimestamp("2026-10-27T10:00:00.000Z", now).getTime(), now);
});

test("webhook HMAC verification rejects replays and accepts a valid envelope", () => {
  const secret = "sandbox-secret";
  const timestamp = "1793095200";
  const payload = { event: "BYPASS", timestamp, data: { deviceNumber: "BR-ASH-001" } };
  const rawBody = Buffer.from(JSON.stringify(payload));
  const signedPayload = JSON.stringify({ event: payload.event, timestamp, data: payload.data });
  const signature = crypto.createHmac("sha256", secret).update(signedPayload).digest("hex");
  const now = Number(timestamp) * 1000;
  assert.equal(verifyAshGridWebhook({ rawBody, signature, timestamp, secret, now }).valid, true);
  assert.equal(verifyAshGridWebhook({ rawBody, signature, timestamp, secret, now: now + 121_000 }).code, "stale-timestamp");
});

test("webhook verification also accepts Section 6 entire-payload data signing", () => {
  const secret = "sandbox-secret";
  const timestamp = "1793095200";
  const payload = { event: "DEVICE_ONLINE", timestamp, deviceNumber: "BR-ASH-001" };
  const rawBody = Buffer.from(JSON.stringify(payload));
  const signedPayload = JSON.stringify({ event: payload.event, timestamp, data: payload });
  const signature = crypto.createHmac("sha256", secret).update(signedPayload).digest("hex");
  const result = verifyAshGridWebhook({
    rawBody,
    signature,
    timestamp,
    secret,
    now: Number(timestamp) * 1000,
  });
  assert.equal(result.valid, true);
  assert.equal(result.signatureStrategy, "event-timestamp-entire-payload");
});

test("configuration keeps outbound commands separately locked", () => {
  const config = getAshGridXConfig({
    ASHGRIDX_ENABLED: "true",
    ASHGRIDX_COMMANDS_ENABLED: "false",
    ASHGRIDX_STAGING_API_BASE_URL: "https://staging.ashgridx.ashgridxapis.com",
    ASHGRIDX_API_KEY: "present",
    ASHGRIDX_WEBHOOK_SECRET: "present",
    ASHGRIDX_DISCONNECT_PATH: "/future/disconnect",
  });
  assert.equal(config.adapterReady, true);
  assert.equal(config.disconnectReady, false);
});
