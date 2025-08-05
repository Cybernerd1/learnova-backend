import { type } from "express/lib/response";
import mongoose from "mongoose";

const communitySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  description: {
    type: String,
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "user",
    required: true,
  },
  mediaFiles: [{ type: mongoose.Schema.ObjectId, ref: "file" }],
  sharedDocuments: [{ type: mongoose.Schema.Types.ObjectId, ref: "File" }],
  messages: [{ type: mongoose.Schema.Types.ObjectId, ref: "Message" }],
  members: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  ],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});


export default mongoose.model("community", communitySchema);