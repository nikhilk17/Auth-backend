import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

export const register =async(req,res)=>{
    const {name,email,password}=req.body;

    if(!name || !email || !password){
        return res.json({success:false,message:'Please fill all the fields'});
    }

    try {
        const existingUser=await userModel.findOne({email});

        if(existingUser)
            return res.json({success:false,message:"Email already exists"})
        const hashedPassword =await bcrypt.hash(password,10);
        const user=new userModel({
            name,
            email,
            password:hashedPassword,
        })

        await user.save();

        const token=jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});
        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV ==='production'?'none':'strict',
            maxAge:7*24*60*60*1000,
        })


        //sending verification email

        const mailOptions={
            from:process.env.SENDER_EMAIL,
            to:email,
            subject:"Welcome To website.Your account has been created",
            text:`Hello ${name},\n\nThank you for registering on our website. Your account has been successfully created.\n\nBest regards,\nWebsite Team`,
        }
        await transporter.sendMail(mailOptions);
        return res.json({success:true,message:'User registered successfully'});
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

export const login=async(req,res)=>{
    const {email,password}=req.body;
    if(!email || !password){
        return res.json({success:false,message:'Please fill all the fields'});
    }
    try {
        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message:'User not found'});
        }

        const isMatch=await bcrypt.compare(password,user.password);
        if(!isMatch){
            return res.json({success:false,message:'Invalid credentials'});
        }

        const token=jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'})
        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV ==='production'?'none':'strict',
            maxAge:7*24*60*60*1000,
        }) 

        return res.json({success:true,message:'Login successful'});
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

export const logout=async(req,res)=>{
    try {
        res.clearCookie('token',{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV ==='production'?'none':'strict',
        })

        return res.json({success:true,message:'Logout successful'});

    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}
export const sendVerifyOtp = async(req,res)=>{
    try {
        const {userId}=req.body;
        const user=await userModel.findById(userId);
        if(user.isAccountVerified){
            return res.json({success:false,message:"Account Already verified"});
        }

        const otp=String(Math.floor(100000+ Math.random()*900000));
        user.verifyOtp=otp;
        user.verifyOtpExpireAt=Date.now()+10*60*1000;
        await user.save();
        const mailOptions={
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:"Account Verification OTP",
            text:`Your OTP is ${otp}. verify your account using this otp.\n\nThis OTP is valid for 10 minutes.\n\nBest regards,\nWebsite Team`,
            html:EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        }

        await transporter.sendMail(mailOptions);
        return res.json({success:true,message:'Verification OTP send on the Email'})
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}


export const verifyEmail=async(req,res)=>{
    const {userId,otp}=req.body;

    if(!userId || !otp){
        return res.json({success:false,message:'Please fill all the fields'});
    }
    try {
        const user=await userModel.findById(userId);
        if(!user){
            return res.json({success:false,message:'User not found'});
        }
        if(user.verifyOtp === '' || user.verifyOtp!==otp){
            return res.json({success:false,message:'Invalid OTP'});
        }

        if(user.verifyOtpExpireAt<Date.now()){
            return res.json({success:false,message:'OTP expired'});
        }

        user.isAccountVerified=true;
        user.verifyOtp='';
        user.verifyOtpExpireAt=0;
        await user.save();
        return res.json({success:true,message:'Email verified successfully'});
    } catch (error) {
        return res.json({success:false,message:error.message});
    }

}


export const isAuthenticated=async(req,res)=>{
    try {
        return res.json({success:true,message:'User is authenticated'});
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

//send Password Reset OTP
export const sendResetOtp=async(req,res)=>{
    const {email}=req.body;
    if(!email){
        return res.json({success:false,message:'Please fill all the fields'});
    }

    try {
        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message:'User not found'});
        }
        const otp=String(Math.floor(100000+ Math.random()*900000));
        user.resetOtp=otp;
        user.resetOtpExpireAt=Date.now()+10*60*1000;
        await user.save();
        const mailOptions={
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:"Password Reset OTP",
            text:`Your OTP is ${otp}. verify your account using this otp.\n\nThis OTP is valid for 10 minutes.\n\nBest regards,\nWebsite Team`,
            html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        }
        await transporter.sendMail(mailOptions);
        return res.json({success:true,message:'Password reset OTP send on the Email'})
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}


//Reset User Password
export const resetPassword= async(req,res)=>{
    const {email,otp,password}=req.body;
    if(!email || !otp || !password){
        return res.json({success:false,message:'Please fill all the fields'});
    }

    try {
        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message:'User not found'});
        }
        if(user.resetOtp === '' || user.resetOtp!== otp){
            return res.json({success:false,message:'Invalid OTP'});
        }
        if(user.resetOtpExpireAt<Date.now()){
            return res.json({success:false,message:'OTP expired'});
        }
        const hashedPassword=await bcrypt.hash(password,10);
        user.password=hashedPassword;
        user.resetOtp='';
        user.resetOtpExpireAt=0;
        await user.save();
        const mailOptions={
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:"Password Reset Successfully",
            text:`Your password has been reset successfully.\n\nBest regards,\nWebsite Team`,
        }
        await transporter.sendMail(mailOptions);
        return res.json({success:true,message:'Password reset successfully'});
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}