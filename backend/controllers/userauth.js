import { User } from "../model/user.models.js";
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken";

const registerUser = async (req, res) => {
  console.log("Incoming Request Body:", req.body); // Log request body to debug
  const { username, email, fullName, password } = req.body;

  if (!username || !email || !fullName || !password) {
    return res.status(400).json({
      success: false,
      message: "All fields are required: username, email, fullName, and password.",
    });
  }

  try {
    const user = new User({ username, email, fullName, password });
    await user.save();
    res.status(201).json({
      success: true,
      message: "User registered successfully!",
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({
      success: false,
      message: "An error occurred during registration.",
      error: err.message,
    });
  }
};
const loginUser=async(req,res)=>{
    const {email,password}=req.body;
    try {
        const checkUser=await User.findOne({email});
        if(!checkUser){
            return res.json({
                success: false,
                message: "User doesn't exists! Please register first",
              });
        }
        const checkPasswordMatch=await bcrypt.compare(
            password,checkUser.password
        );
        if (!checkPasswordMatch)
            return res.json({
              success: false,
              message: "Incorrect password! Please try again",
            });
        const token=jwt.sign({
            id:checkUser._id,
            role:checkUser.role,
            email:checkUser.email,
            username:checkUser.username,
        },
        process.env.ACCESS_TOKEN_SECRET,
        
         { expiresIn:process.env.ACCESS_TOKEN_EXPIRY}
    );

    res.cookie("token",token,{httpOnly:true,secure:process.env.NODE_ENV ==="production"}).json({
        success:true,
        message:"logged in succcesfully",
         user:{
            email: checkUser.email,
            role: checkUser.role,
            id: checkUser._id,
            username: checkUser.username,
    
         }

    })

    } catch (error) {
        console.log(e);
    res.status(500).json({
      success: false,
      message: "Some error occured",
    });
    }
}

const logoutUser = (req, res) => {
    res.clearCookie("token").json({
      success: true,
      message: "Logged out successfully!",
    });
  };


  const authMiddleware = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token)
      return res.status(401).json({
        success: false,
        message: "Unauthorised user!",
      });
  
    try {
      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
      req.user = decoded;
      next();
    } catch (error) {
      res.status(401).json({
        success: false,
        message: "Unauthorised user!",
      });
    }
  };


  export {registerUser,loginUser,logoutUser,authMiddleware}
