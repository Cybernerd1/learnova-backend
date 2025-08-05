import mongoose from "mongoose";

const classroomSchema = new mongoose.Schema({
    name:{type:String, required:true},  
    subject:{type:String, required:true},
    code:{type:String,required:true,unique:true},

    createdBy:{type:mongoose.Schema.Types.ObjectId, ref:'user',required:true},

    privacy:{ type:String,
        enum:["anyone","only-approved"],
        default:"anyone",
    },

    isCommunity:{type:Boolean,default:false},

    members:[{type:mongoose.Schema.Types.ObjectId, ref:'user'}],

    lessons:[{type:mongoose.Schema.Types.ObjectId,ref:'Lesson'}],
    favourites:[{type:mongoose.Schema.Types.ObjectId,ref:'Lesson'}],

},{timestamps:true})


export default mongoose.model("Classroom",classroomSchema)