import mongoose from "mongoose";

const trainingSettingsSchema = new mongoose.Schema(
  {
    cohortName: { type: String, default: "BuiltRight Solar Installation Training", trim: true },
    liveClassUrl: { type: String, default: "", trim: true },
    brochureUrl: { type: String, default: "", trim: true },
  },
  { timestamps: true }
);

const TrainingSettings = mongoose.model("TrainingSettings", trainingSettingsSchema);

export default TrainingSettings;
