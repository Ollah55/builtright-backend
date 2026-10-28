import crypto from "crypto";

export const ASHGRIDX_EVENTS = Object.freeze([
  "DEVICE_ONLINE",
  "DEVICE_OFFLINE",
  "BYPASS",
  "BYPASS_REVERSED",
]);

const readBoolean = (value) => String(value || "").toLowerCase() === "true";

export function parseAshGridTimestamp(value, now = Date.now()) {
  if (value === undefined || value === null || value === "") return null;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    const milliseconds = numeric > 10_000_000_000 ? numeric : numeric * 1000;
    const date = new Date(milliseconds);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  if (date.getTime() > now + 86_400_000) return null;
  return date;
}

export function normalizeAshGridEvent(payload = {}) {
  const data = payload.data && typeof payload.data === "object" ? payload.data : payload;
  const eventName = String(payload.event || payload.type || data.event || "UNKNOWN").toUpperCase();
  const deviceIdentifier =
    data.deviceNumber ||
    data.deviceId ||
    data.customerDeviceId ||
    payload.deviceNumber ||
    payload.deviceId ||
    payload.customerDeviceId ||
    "";
  return { eventName, data, deviceIdentifier: String(deviceIdentifier || "").trim() };
}

export function ashGridEventSemantics(eventName) {
  const event = String(eventName || "UNKNOWN").toUpperCase();
  if (event === "DEVICE_ONLINE") {
    return {
      connectivity: "online",
      protectionState: null,
      tamperState: null,
      alertType: "device-online",
      severity: "info",
      title: "AshGridX device online",
      detail: "Device connectivity has been restored.",
    };
  }
  if (event === "DEVICE_OFFLINE") {
    return {
      connectivity: "offline",
      protectionState: null,
      tamperState: null,
      alertType: "offline",
      severity: "warning",
      title: "AshGridX device offline",
      detail: "The device stopped reporting and requires investigation.",
    };
  }
  if (event === "BYPASS") {
    return {
      connectivity: null,
      protectionState: "bypass",
      tamperState: "confirmed",
      alertType: "protection-bypass",
      severity: "critical",
      title: "AshGridX bypass or tamper signal",
      detail: "AshGridX reported a BYPASS event. Inspect the assigned device, relay wiring and customer site immediately.",
    };
  }
  if (event === "BYPASS_REVERSED") {
    return {
      connectivity: null,
      protectionState: "normal",
      tamperState: "clear",
      alertType: "protection-restored",
      severity: "info",
      title: "AshGridX bypass reversed",
      detail: "AshGridX reported that the bypass condition has been reversed.",
    };
  }
  return {
    connectivity: null,
    protectionState: null,
    tamperState: null,
    alertType: "other",
    severity: "info",
    title: `AshGridX ${event.toLowerCase().replaceAll("_", " ")}`,
    detail: "Provider event received and retained for review.",
  };
}

export function verifyAshGridWebhook({ rawBody, signature, timestamp, secret, toleranceSeconds = 120, now = Date.now() }) {
  if (!secret) return { valid: false, code: "not-configured" };
  if (!rawBody || !signature) return { valid: false, code: "missing-signature" };
  let parsed;
  try {
    parsed = JSON.parse(Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : String(rawBody));
  } catch {
    return { valid: false, code: "invalid-json" };
  }
  const effectiveTimestamp = timestamp || parsed.timestamp;
  if (!effectiveTimestamp) return { valid: false, code: "missing-timestamp" };
  const occurredAt = parseAshGridTimestamp(effectiveTimestamp, now);
  if (!occurredAt) return { valid: false, code: "invalid-timestamp" };
  if (Math.abs(now - occurredAt.getTime()) > toleranceSeconds * 1000) {
    return { valid: false, code: "stale-timestamp" };
  }
  // Section 6 defines an event/timestamp/data JSON string, with data described
  // as the entire event payload. Support both the nested example and that
  // literal reading while the final sample payload is still being supplied.
  const signingCandidates = [];
  if (Object.prototype.hasOwnProperty.call(parsed, "data")) {
    signingCandidates.push({
      strategy: "event-timestamp-nested-data",
      value: JSON.stringify({
        event: parsed.event,
        timestamp: String(effectiveTimestamp),
        data: parsed.data,
      }),
    });
  }
  signingCandidates.push({
    strategy: "event-timestamp-entire-payload",
    value: JSON.stringify({
      event: parsed.event,
      timestamp: String(effectiveTimestamp),
      data: parsed,
    }),
  });
  const supplied = String(signature).replace(/^sha256=/i, "").trim();
  const suppliedBuffer = Buffer.from(supplied, "utf8");
  const match = signingCandidates.find(({ value }) => {
    const expected = crypto.createHmac("sha256", secret).update(value).digest("hex");
    const expectedBuffer = Buffer.from(expected, "utf8");
    return expectedBuffer.length === suppliedBuffer.length && crypto.timingSafeEqual(expectedBuffer, suppliedBuffer);
  });
  return {
    valid: Boolean(match),
    code: match ? "ok" : "invalid-signature",
    signatureStrategy: match?.strategy || null,
    parsed,
    occurredAt,
  };
}

export function getAshGridXConfig(env = process.env) {
  const environment = env.ASHGRIDX_ENVIRONMENT === "production" ? "production" : "staging";
  const stagingBaseUrl = env.ASHGRIDX_STAGING_API_BASE_URL || env.ASHGRIDX_API_BASE_URL || "";
  const productionBaseUrl = env.ASHGRIDX_PRODUCTION_API_BASE_URL || "";
  const baseUrl = environment === "production" ? productionBaseUrl : stagingBaseUrl;
  const enabled = readBoolean(env.ASHGRIDX_ENABLED);
  const commandsEnabled = readBoolean(env.ASHGRIDX_COMMANDS_ENABLED);
  const apiKeyPresent = Boolean(env.ASHGRIDX_API_KEY);
  const webhookConfigured = Boolean(env.ASHGRIDX_WEBHOOK_SECRET);
  const disconnectPath = env.ASHGRIDX_DISCONNECT_PATH || "";
  const activationTokenPath = env.ASHGRIDX_ACTIVATION_TOKEN_PATH || "";
  return {
    environment,
    baseUrl,
    stagingBaseUrl,
    productionBaseUrl,
    enabled,
    commandsEnabled,
    apiKeyPresent,
    webhookConfigured,
    credentialsPresent: Boolean(baseUrl && apiKeyPresent),
    webhookReady: enabled && webhookConfigured,
    adapterReady: enabled && Boolean(baseUrl && apiKeyPresent && webhookConfigured),
    disconnectReady: enabled && commandsEnabled && Boolean(baseUrl && apiKeyPresent && disconnectPath),
    activationTokenReady: enabled && commandsEnabled && Boolean(baseUrl && apiKeyPresent && activationTokenPath),
    disconnectPath,
    activationTokenPath,
  };
}
