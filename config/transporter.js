// import nodemailer from 'nodemailer';

// const transporter = nodemailer.createTransport({
//     hoste: 'smtp-relay.brevo.com',
//     port:587,
//     // secure:false,
//     auth:{
//         user:process.env.SMTP_USER,
//         pass: process.env.SMTP_PASS
//     }
// });

// export default transporter;
import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config(); // ✅ Load .env


console.log("Using SMTP config:", {
    host: "smtp-relay.brevo.com",
    user: process.env.SMTP_USER,
  });
  
const transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com", // ✅ Ensure this is NOT 127.0.0.1
  port: 587,
  secure: false, // false for STARTTLS
  auth: {
    user: process.env.SMTP_USER, // ✅ Your Brevo SMTP email
    pass: process.env.SMTP_PASS, // ✅ Your Brevo SMTP password
  },
});

export default transporter;
