export const INSTALLATION_TRANSITIONS = Object.freeze({
  "in-progress": Object.freeze({
    from: "scheduled",
    projectStatus: "installation-in-progress",
    timestamp: "startedAt",
    message: "Installation work has started at your property.",
  }),
  "testing-commissioning": Object.freeze({
    from: "in-progress",
    projectStatus: "installation-in-progress",
    timestamp: "testingStartedAt",
    message: "Installation is complete and testing and commissioning are now in progress.",
  }),
  completed: Object.freeze({
    from: "testing-commissioning",
    projectStatus: "completed",
    timestamp: "completedAt",
    message: "Testing and commissioning are complete. Your BuiltRight solar project has been marked completed.",
  }),
});

export function installationSchedulingGate({ assignmentStatus, projectStatus, bankStatus }) {
  if (assignmentStatus !== "completed") return { allowed: false, reason: "assessment-incomplete" };
  if (bankStatus !== "disbursed") return { allowed: false, reason: "disbursement-unconfirmed" };
  if (!["disbursed", "order-created"].includes(projectStatus)) return { allowed: false, reason: "project-not-released" };
  return { allowed: true, reason: "funding-confirmed" };
}

export function installationTransition(nextStatus) {
  return INSTALLATION_TRANSITIONS[nextStatus] || null;
}
