// models/fileModel.js

import mongoose from 'mongoose';

const fileSchema = new mongoose.Schema({
  fileUrl: { type: String, required: true },
  fileName: { type: String, required: true },
  fileType: {
    type: String,
    enum: ['image', 'video', 'audio', 'pdf', 'doc', 'zip', 'ppt', 'xls', 'other'],
    required: true
  },

  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

  // Context: where is this file used?
  context: {
    type: String,
    enum: ['chat', 'classroom', 'group', 'community'],
    required: true
  },

  // Links the file to the specific source (optional based on context)
  classroomId: { type: mongoose.Schema.Types.ObjectId, ref: 'Classroom' },
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
  messageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  communityId: { type: mongoose.Schema.Types.ObjectId, ref: 'Community' },

  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model('file', fileSchema);
