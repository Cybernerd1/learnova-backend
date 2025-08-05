import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";
import session from 'express-session';
import passport from 'passport';
import './config/passport.js';

dotenv.config();
connectDB();
const app = express();
const port = process.env.PORT || 5000;

const allowedOrigins = ["http://localhost:5173","http://localhost:3000",
    process.env.FRONTEND_URL, "*"].filter(Boolean);

app.use(express.json());
app.use(cookieParser());
// app.use(cors({ origin: allowedOrigins, credentials: true }));

app.use(cors({ 
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));
  
app.use(passport.initialize());
app.use(passport.session());

// Api endpoints
app.get("/", (req, res) => res.send("Api working fine"));
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        success: false, 
        message: 'Something went wrong!' 
    });
});

// Handle 404
app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        message: 'Route not found' 
    });
});

app.listen(port, () => {
  console.log(`server is listening on port,${port}`);
});
