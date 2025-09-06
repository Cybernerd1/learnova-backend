import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';


// Rate limiting middleware for classroom creation
export const createClassroomRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each user to 5 classroom creations per windowMs
    message: {
        success: false,
        message: "Too many classroom creation attempts, please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Validation middleware
export const validateClassroomCreation = [
    body('name')
        .trim()
        .isLength({ min: 1, max: 100 })
        .withMessage('Name must be between 1 and 100 characters')
        .matches(/^[a-zA-Z0-9\s\-_.,()]+$/)
        .withMessage('Name contains invalid characters'),
    
    body('subject')
        .trim()
        .isLength({ min: 1, max: 50 })
        .withMessage('Subject must be between 1 and 50 characters')
        .matches(/^[a-zA-Z0-9\s\-_.,()]+$/)
        .withMessage('Subject contains invalid characters'),
    
    body('privacy')
        .optional()
        .isIn(['public', 'private'])
        .withMessage('Privacy must be either public or private'),
    
    body('isCommunity')
        .optional()
        .isBoolean()
        .withMessage('isCommunity must be a boolean value')
];