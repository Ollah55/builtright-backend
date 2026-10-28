export function assignmentRevision(value) {
  const revision = Number(value);
  return Number.isSafeInteger(revision) && revision >= 0 ? revision : 0;
}
export function assignmentRevisionFilter(value) {
  const revision = assignmentRevision(value);
  if (revision === 0) {
    return {
      $or: [
        { "installerAssignment.revision": 0 },
        { "installerAssignment.revision": { $exists: false } },
      ],
    };
  }
  return { "installerAssignment.revision": revision };
}

export function installerAssignmentWriteFilter({
  projectId,
  installerId,
  revision,
  statuses,
}) {
  return {
    _id: projectId,
    "installerAssignment.installer": installerId,
    ...(Array.isArray(statuses) && statuses.length
      ? { "installerAssignment.status": { $in: statuses } }
      : {}),
    ...assignmentRevisionFilter(revision),
  };
}

