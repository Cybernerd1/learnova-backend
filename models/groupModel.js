import mongoose from 'mongoose';

const groupSchema = new mongoose.Schema({
    name:{type:String, required:true},
    createdBy:{type:mongoose.Schema.Types.ObjectId,ref:'user'},
    members:[{type:mongoose.Schema.Types.ObjectId,ref:'user'}],
    avatar:String,
},{
    timestamps:true
})

export default mongoose.model('group',groupSchema);