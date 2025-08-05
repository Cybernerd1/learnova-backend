import mongoose from "mongoose";

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "user", required: true },
  // message type:community,group or personal
  type: {
    type: String,
    enum: ["community", "group", "personal"],
    required: true,
  },

  // for personal chat(direct)
  recepient: { type: mongoose.Schema.Types.ObjectId, ref: "user" },

  // group
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: "group" },

  // community
  communityId: { type: mongoose.Schema.Types.ObjectId, ref: "community" },

  text: String,
  media: { type: mongoose.Schema.Types.ObjectId, ref: "Media" }, // optional

  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("Message", messageSchema);
