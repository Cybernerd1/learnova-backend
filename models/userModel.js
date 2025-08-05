import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, uniques: true },
    password: { type: String, required: true },

    verifyOtp: { type: String, default: "" },
    verifyOtpExpireAt: { type: Number, default: 0 },
    isAccountVerified: { type: Boolean, default: false },
    resetOtp: { type: String, default: "" },
    resetOtpExpireAt: { type: Number, default: 0 },

    profilePic: { type: String, default: "" },

    classroom: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Classroom",
      default: null,
    },

    joinedClasses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Classroom" }],
    createdClasses: [
      { type: mongoose.Schema.Types.ObjectId, ref: "Classroom" },
    ],
  },
  { timestamps: true }
);

const userModel = mongoose.models.user || mongoose.model("user", userSchema);
export default userModel;
