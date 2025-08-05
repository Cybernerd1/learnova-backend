import express from "express";
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';

dotenv.config();

const app= express();

app.use(cors(({ origin: allowedOrigins, credentials: true })));
app.use(express.json());

const port = process.env.PORT || 5000;
app.listen(port,()=>{
    console.log(`server is listening on port`,${});
})