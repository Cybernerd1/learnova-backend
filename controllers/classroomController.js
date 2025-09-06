import userModel from "../models/userModel";
import classroomModel from "../models/classroomModel";
import fileModel from "../models/fileModel";
import { customAlphabet } from "nanoid";
import { createClassroomRateLimit, validateClassroomCreation } from "../middlewares/classroom.middleware";
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';

export const createClassroom = async (req,res)=>{
    try {
        const errorz = validationResult(req);
        if(!errorz.isEmpty()){
            return res.status(400).json({
                success:false,
                message:"Kindly check the details you have provided",
                errors:errorz.array()
            })
        }

        if(!req.user || !req.user._id){
            return res.status(401).json({
                success:false,
                message:"Authentication required"
            })
        }
        const name = xss(req.body.name.trim()); 
        const subject = xss(req.body.subject.trim());
        const privacy = req.body.privacy || 'public';
        const isCommunity = req.body.isCommunity || false;
        const createdBy = req.user._id;
     
        if(!name || !subject ){
            return res.status(400).json({
                success:false,
                message:"Name and Subject name are required"
            })
        }

            // Classroom unique code
            const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            const generateClassCode = customAlphabet(alphabet, 8);
            let code;
            let unique = false;
            while(!unique){
                code = generateClassCode();
                let exists = await classroomModel.findOne({code}).lean();
                if(!exists) unique = true;
            }
            const newClassroom = new classroomModel({
                name,
                subject,
                code,
                privacy,
                isCommunity,
                createdBy,
                createdAt: new Date(),
                updatedAt: new Date()
            })

            const savedClass = await newClassroom.save();
            if(!savedClass){
                return res.status(500).json({
                    success:false,
                    message:"Error creating classroom"
                })
            }
            const classroomResponse = {
                _id: savedClass._id,
                name: savedClass.name,
                subject: savedClass.subject,
                code: savedClass.code,
                privacy: savedClass.privacy,
                isCommunity: savedClass.isCommunity,
                createdAt: savedClass.createdAt
            }
            console.log(`Classroom created: ${savedClass._id} by user: ${createdBy}`);

            return res.status(201).json({
                success:true,
                message:"Classroom created successfully",
                data:{
                    classroom:newClassroom
                }
            })

        // 
    }catch (error) {
        console.error('Classroom creation error:', {
            error: error.message,
            userId: req.user?._id,
            timestamp: new Date()
        });

        // Handle specific database errors
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                message: "Invalid data provided",
                errors: Object.values(error.errors).map(err => err.message)
            });
        }

        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: "A classroom with this code already exists"
            });
        }

        // Generic error response (don't expose internal errors)
        return res.status(500).json({
            success: false,
            message: "An error occurred while creating the classroom"
        });
    }
}

ex