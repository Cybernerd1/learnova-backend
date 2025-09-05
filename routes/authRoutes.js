import express from "express";
import {
  isAuthenticated,
  loginUser,
  logout,
  registerUser,
  resetPassword,
  sendResetOtp,
  sendVerifyOtp,
  verifyEmail,
  otpLogin,
  refreshToken,
  sendLoginOtp
} from "../controllers/authController.js";
import userAuth from "../middlewares/userAuth.js";
import { otpLimiter, loginLimiter } from "../middlewares/ratelimiter.js";
import passport from "passport";
import { authRateLimiter } from "../middlewares/ratelimiter.js";


const authRouter = express.Router();
authRouter.use(authRateLimiter);

authRouter.post("/register", registerUser);
authRouter.post("/login", loginLimiter, loginUser);
authRouter.post("/logout", logout);
authRouter.post("/send-verify-otp", otpLimiter, sendVerifyOtp);
authRouter.post("/send-login-otp", otpLimiter, sendLoginOtp);
authRouter.post("/verify-account", verifyEmail);
authRouter.get("/is-auth", userAuth, isAuthenticated);
authRouter.post("/send-reset-otp", otpLimiter, sendResetOtp);
authRouter.post("/reset-password", resetPassword);
authRouter.post("/refresh-token", refreshToken);
authRouter.post("/otp-login",loginLimiter, otpLogin);

// Google OAuth
authRouter.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
authRouter.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

    // Redirect frontend with token
    res.redirect(`${process.env.CLIENT_URL}/auth/success?token=${token}`);
  }
);

export default authRouter