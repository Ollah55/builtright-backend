import mongoose from "mongoose";

const trainingSettingsSchema = new mongoose.Schema(
  {
    cohortName: { type: String, default: "BuiltRight Solar Installation Training", trim: true },
    liveClassUrl: { type: String, default: "", trim: true },
    brochureUrl: { type: String, default: "", trim: true },
    meetingNumber: { type: String, default: "", trim: true },
    meetingPasscode: { type: String, default: "", trim: true },
    liveSessionActive: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const TrainingSettings = mongoose.model("TrainingSettings", trainingSettingsSchema);

export default TrainingSettings;
