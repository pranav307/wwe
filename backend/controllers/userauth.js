import { User } from "../model/user.models.js";
import bcrypt from "bcryptjs";
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


const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validation - check if email and password are provided
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required.",
      });
    }

    // Check if user exists
    const checkUser = await User.findOne({ email });
    if (!checkUser) {
      return res.status(400).json({
        success: false,
        message: "User doesn't exist! Please register first.",
      });
    }

    // Verify password
    const checkPasswordMatch = await bcrypt.compare(password, checkUser.password);
    if (!checkPasswordMatch) {
      return res.status(400).json({
        success: false,
        message: "Incorrect password! Please try again.",
      });
    }

    // Generate token
    const token = jwt.sign(
      {
        id: checkUser._id,
        role: checkUser.role,
        email: checkUser.email,
        username: checkUser.username,
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
    );

    // Return response with token
    /* res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production" }).json({
      success: true,
      message: "Logged in successfully",
      user: {
        email: checkUser.email,
        role: checkUser.role,
        id: checkUser._id,
        username: checkUser.username,
      },
    }); */
    res.status(200).json({
      success: true,
      message: "logged in successfully",
      token,
      user: {
        email: checkUser.email,
        role: checkUser.role,
        id: checkUser._id,
        username: checkUser.username,
      },
    })
  } catch (error) {
    console.error("Error during login:", error);

    res.status(500).json({
      success: false,
      message: "Some error occurred while logging in.",
    });
  }
};

const logoutUser = (req, res) => {
  res.clearCookie("token").json({
    success: true,
    message: "Logged out successfully!",
  });
};

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split('')[1]

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized user!",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Error during token verification:", error);

    res.status(401).json({
      success: false,
      message: "Unauthorized user!",
    });
  }
};

export { registerUser, loginUser, logoutUser, authMiddleware };
