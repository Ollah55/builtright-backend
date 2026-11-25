import mongoose from "mongoose";

export const activeMaintenanceTechnician = Object.freeze({ role: "installer", isActive: true });

export async function resolveMaintenanceTechnician(id, findTechnician) {
  if (id === null) return null;
  if (typeof id === "string" && mongoose.isObjectIdOrHexString(id)) {
    const technician = await findTechnician({ _id: id, ...activeMaintenanceTechnician });
    if (technician) return technician._id;
  }
  throw Object.assign(new Error("Choose an active technician or select Unassigned."), { statusCode: 400 });
}
