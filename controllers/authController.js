import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/transporter.js";
import {
  EMAIL_VERIFY_TEMPLATE,
  PASSWORD_RESET_TEMPLATE,
} from "../config/emailTemplates.js";
import { createAccessToken, createRefreshToken } from "../utils/token.js";

export const refreshToken = async (req, res) => {
  //   const refresh = req.cookies.refreshToken;
  // if (!refresh) {
  //   return res.status(401).json({ success: false, message: "No refresh token" });
  // }
  // const decoded = jwt.verify(refresh, process.env.REFRESH_SECRET);

  const { refreshToken } = req.cookies;
  if (!refreshToken)
    return res
      .status(401)
      .json({ success: false, message: "No refresh token" });

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    if (!decoded?.id) {
      return res
        .status(403)
        .json({ success: false, message: "Invalid refresh token" });
    }

    const accessToken = createAccessToken(decoded.id);
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000,
    });
    res.json({ success: true });
  } catch (err) {
    res.status(403).json({ success: false, message: "Invalid refresh token" });
  }
};

export const registerUser = async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.json({ success: false, message: "Passwords do not match" });
  }

  if (!name || !email || !password || !confirmPassword) {
    return res.json({ success: false, message: "All fields are required" });
  }

  try {
    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      return res.json({ success: false, message: "user already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new userModel({
      name,
      email,
      password: hashedPassword,
      isAccountVerified: false,
    });

    await user.save();

    // const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    //   expiresIn: "30d",
    // });
    // //jwt.sign - Creates a JWT token using the user's _id as the payload.

    // // res.cookie(name, value, options)
    // res.cookie("token", token, {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === "production",
    //   sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    //   maxAge: 30 * 24 * 60 * 60 * 1000,
    // });

    const accessToken = createAccessToken(user._id);
    const refreshToken = createRefreshToken(user._id);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // sending welcome email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "welcome to LearnOva",
      text: "Welcome to LearnOva, we are glad to have you on board.",
    };
    await transporter.sendMail(mailOptions);

    return res.json({ success: true, message: "User registered successfully" });
    // return res.json({success:true, message:"User registered successfully", userId:user._id, token});
  } catch (error) {
    res.json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
};

// export const loginUser = async (req, res) => {
//   const { email, password } = req.body;
//   if (!email || !body) {
//     return res.json({ success: false, message: "All fields are required" });
//   }

//   try {
//     const user = await userModel.findOne({ email });
//     if (!user) {
//       return res.json({ success: false, message: "User does not exist" });
//     }

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.json({ success: false, message: "Invalid credentials" });
//     }

//     if (!user.isAccountVerified) {
//       return res.json({
//         success: false,
//         message: "Kindly verify your email first",
//       });
//     }

//     const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
//       expiresIn: "30d",
//     });

//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
//       maxAge: 30 * 24 * 60 * 60 * 1000,
//     });

//     return res.json({ success: true, message: "User logged in successfully" });
//     // return res.json({success:true, message:"User logged in successfully", userId:user._id, token});
//   } catch (error) {
//     return res.json({ success: false, message: error.message });
//   }
// };

export const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({ success: false, message: "All fields are required" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User does not exist" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    if (!user.isAccountVerified) {
      return res.json({
        success: false,
        message: "Kindly verify your email first",
      });
    }

    const accessToken = createAccessToken(user._id);
    const refreshToken = createRefreshToken(user._id);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ success: true, message: "User logged in successfully" });
  } catch (error) {
    return res.json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
};

export const logout = async (req, res) => {
  try {
    // res.clearCookie("token", {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === "production",
    //   sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    // });
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });
    return res.json({ success: true, message: "User logged out successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

export const sendVerifyOtp = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.json({ success: false, message: "Email is required" });
    }
    // const user = await userModel.findById(userId);
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }
    if (user.isAccountVerified) {
      return res.json({ success: false, message: "Account already verified" });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 10 * 60 * 1000; // 10 minutes from now
    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account verification Otp",
      // text: `Your OTP is ${otp}. verify your account using this otp`,
      html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace(
        "{{email}}",
        user.email
      ),
    };
    await transporter.sendMail(mailOptions);
    res.json({
      success: true,
      message: "Verification OTP sent on Email",
    });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.json({ success: false, message: "Missing details" });
  }

  try {
    // const user = await userModel.findById(userId);
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    if (user.verifyOtp === "" || user.verifyOtp !== String(otp)) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP expired" });
    }

    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;

    await user.save();
    return res.json({ success: true, message: "Email verified successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

export const isAuthenticated = async (req, res) => {
  try {
    const { accessToken } = req.cookies;

    if (!accessToken) {
      return res
        .status(401)
        .json({ success: false, message: "User not logged in" });
    }

    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
    if (!decoded?.id) {
      return res.status(401).json({ success: false, message: "Invalid token" });
    }
    const user = await userModel.findById(decoded.id).select("-password");
    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid token. User not found." });
    }

    return res.status(200).json({ success: true, user });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Token expired or invalid",
      error: error.message,
    });
  }
};

// send password reset otp
export const sendResetOtp = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.json({ success: false, message: "Email is required" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
    await user.save();
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account verification Otp",
      // text: `Your OTP for resetting your password is ${otp}. use this OTP to proceed with resetting your password`,
      html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace(
        "{{email}}",
        user.email
      ),
    };
    await transporter.sendMail(mailOptions);
    res.json({
      success: true,
      message: " OTP sent to your Email",
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// reset user password
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.json({
      success: false,
      message: " Email, OTP, and newPassword are required",
    });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User Not found" });
    }

    if (user.resetOtp === "" || user.resetOtp !== String(otp)) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    if (user.resetOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP Expired" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;

    await user.save();

    return res.json({
      success: true,
      message: " Password has been reset successfully",
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// export const otpLogin = async (req, res) => {
//   const { email, otp } = req.body;
//   const user = await userModel.findOne({ email });

//   if (
//     !user ||
//     user.verifyOtp !== String(otp) ||
//     user.verifyOtpExpireAt < Date.now()
//   ) {
//     return res.json({ success: false, message: "Invalid OTP" });
//   }

//   user.verifyOtp = "";
//   user.verifyOtpExpireAt = 0;
//   await user.save();

//   const token = createAccessToken(user._id);
//   const refresh = createRefreshToken(user._id);

//   res.cookie("accessToken", token, { httpOnly: true, maxAge: 15 * 60 * 1000 });
//   res.cookie("refreshToken", refresh, {
//     httpOnly: true,
//     maxAge: 7 * 24 * 60 * 60 * 1000,
//   });

//   res.json({ success: true });
// };

export const otpLogin = async (req, res) => {
  const { email, otp } = req.body;

  // Validate required fields
  if (!email || !otp) {
    return res.json({ success: false, message: "Email and OTP are required" });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    // Check OTP validity
    if (user.verifyOtp !== String(otp)) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP expired" });
    }

    // Clear OTP after successful verification
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;
    await user.save();

    // Generate tokens
    const accessToken = createAccessToken(user._id);
    const refreshToken = createRefreshToken(user._id);

    // Set cookies with consistent settings
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.json({
      success: true,
      message: "Login successful",
    });
  } catch (error) {
    return res.json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
};
