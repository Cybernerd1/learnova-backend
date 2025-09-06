// config/passport.js
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import dotenv from 'dotenv';
import userModel from '../models/userModel.js';

import crypto from "crypto";

function generateRandomPassword(length = 8) {
  return crypto.randomBytes(length).toString("hex"); // secure random string
}


// Load environment variables
dotenv.config();

// Check if required environment variables are present
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    console.error(' Google OAuth credentials missing!');
    console.error('Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file');
    process.exit(1);
}

// console.log('✅ Google OAuth credentials loaded');
// console.log('Client ID:', process.env.GOOGLE_CLIENT_ID ? 'Present' : 'Missing');
// console.log('Client Secret:', process.env.GOOGLE_CLIENT_SECRET ? 'Present' : 'Missing');

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('Google OAuth callback received for user:', profile.displayName);
        
        // Check if user already exists in database
        let existingUser = await userModel.findOne({ 
            $or: [
                { googleId: profile.id },
                { email: profile.emails[0].value }
            ]
        });

        if (existingUser) {
            console.log('Existing user found:', existingUser.email);
            
            // If user exists but doesn't have googleId, add it
            if (!existingUser.googleId) {
                existingUser.googleId = profile.id;
                existingUser.isAccountVerified = true;
                existingUser.authProvider = 'google';
                await existingUser.save();
                console.log('Updated existing user with Google ID');
            }
            return done(null, existingUser);
        }

        // Create new user if doesn't exist
        console.log('Creating new user for:', profile.emails[0].value);
        const randomPassword = generateRandomPassword();
        const newUser = new userModel({
            googleId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            profilePicture: profile.photos[0]?.value || '',
            isAccountVerified: true,
            authProvider: 'google',
            password: randomPassword // Auto generated 8 digit password for OAuth users
        });

        const savedUser = await newUser.save();
        console.log('New user created:', savedUser.email);
        return done(null, savedUser);

    } catch (error) {
        console.error('Google OAuth error:', error);
        return done(error, null);
    }
}));

// Serialize user for session
passport.serializeUser((user, done) => {
    console.log('Serializing user:', user._id);
    done(null, user._id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
    try {
        const user = await userModel.findById(id).select('-password');
        console.log('Deserializing user:', user?.email);
        done(null, user);
    } catch (error) {
        console.error('Deserialize error:', error);
        done(error, null);
    }
});

export default passport;