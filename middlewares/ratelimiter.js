import rateLimit from "express-rate-limit";

export const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 requests per window
    message: "Too many requests from this IP, please try again after 15 minutes",
    standardHeaders: true,
    legacyHeaders: false,
});

export const otpLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 1, // 1 OTP request per minute
    message: "Too many OTP requests from this IP, please try again after 1 minute",
    standardHeaders: true,
    legacyHeaders: false,
});

export const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5, // 5 login attempts per 10 minutes
    message: "Too many login attempts. Try again later.",
    standardHeaders: true,
    legacyHeaders: false,
});

export const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 verification attempts per 15 minutes
    message: "Too many verification attempts. Please wait.",
    standardHeaders: true,
    legacyHeaders: false,
});
