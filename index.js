const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const bcrypt = require('bcrypt');
const validator = require('validator');
var app = express();

app.set('view engine', 'ejs');
 
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const mongoose = require("mongoose");
mongoose.connect("mongodb+srv://eng22cy0053:kSNNjT0zHq3SZpb2@cluster1.mfphlgv.mongodb.net/?retryWrites=true&w=majority&appName=Cluster1");

// Define schema with validation
const userSchema = new mongoose.Schema({
   email: {
     type: String,
     required: true,
     unique: true,
     lowercase: true,
     validate: [validator.isEmail, 'Please provide a valid email']
   },
   password: {
     type: String,
     required: true,
     minlength: 6
   },
   createdAt: {
     type: Date,
     default: Date.now
   }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Hash password with cost of 12
    const hashedPassword = await bcrypt.hash(this.password, 12);
    this.password = hashedPassword;
    next();
  } catch (error) {
    next(error);
  }
});

// Instance method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

// Password validation function
function validatePassword(password) {
  const minLength = 6;
  const maxLength = 20;
  
  // Check length
  if (password.length < minLength || password.length > maxLength) {
    return {
      isValid: false,
      message: `Password must be between ${minLength} and ${maxLength} characters long`
    };
  }
  
  // Check for at least one lowercase letter
  if (!/[a-z]/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one lowercase letter'
    };
  }
  
  // Check for at least one uppercase letter
  if (!/[A-Z]/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one uppercase letter'
    };
  }
  
  // Check for at least one number
  if (!/\d/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one number'
    };
  }
  
  return { isValid: true };
}

// Email validation function
function validateEmail(email) {
  return validator.isEmail(email);
}

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login", { error: null });
});

app.get("/register", function(req, res){
  res.render("register", { error: null });
});

// POST route for login with enhanced validation
app.post("/login", async function(req, res) {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // Validate email format
    if (!validateEmail(email)) {
      return res.render("login", { 
        error: "Please enter a valid email address" 
      });
    }

    // Check if password is provided
    if (!password) {
      return res.render("login", { 
        error: "Password is required" 
      });
    }

    // Find user by email
    const foundUser = await User.findOne({ email: email.toLowerCase() });

    if (!foundUser) {
      return res.render("login", { 
        error: "No account found with this email address" 
      });
    }

    // Compare password using bcrypt
    const isPasswordValid = await foundUser.comparePassword(password);

    if (isPasswordValid) {
      // Successful login - redirect to secrets page
      res.render("secrets");
    } else {
      res.render("login", { 
        error: "Incorrect password" 
      });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.render("login", { 
      error: "An error occurred during login. Please try again." 
    });
  }
});

// POST route for register with enhanced validation
app.post("/register", async function(req, res) {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // Validate email format
    if (!validateEmail(email)) {
      return res.render("register", { 
        error: "Please enter a valid email address" 
      });
    }

    // Validate password format
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.render("register", { 
        error: passwordValidation.message 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.render("register", { 
        error: "An account with this email already exists" 
      });
    }

    // Create new user
    const newUser = new User({
      email: email.toLowerCase(),
      password: password // Will be hashed by the pre-save middleware
    });

    await newUser.save();
    console.log("User registered successfully:", email);
    
    // Redirect to login page after successful registration
    res.render("login", { 
      success: "Registration successful! Please log in with your credentials.",
      error: null 
    });

  } catch (err) {
    console.log("Registration error:", err);
    
    if (err.code === 11000) {
      // Duplicate key error
      res.render("register", { 
        error: "An account with this email already exists" 
      });
    } else {
      res.render("register", { 
        error: "Registration failed. Please try again." 
      });
    }
  }
});

// Protected dashboard route
app.get("/dashboard", function(req, res){
  res.render("dashboard", { 
    user: {
      email: "Please log in to view your information",
      memberSince: ""
    }
  });
});

app.get("/secrets", function(req, res){
  res.render("secrets");
});

app.get("/submit", function(req, res){
  res.render("submit");
});

app.post("/submit", function(req, res){
  console.log("Secret submitted:", req.body.secret);
  res.redirect("/secrets");
});

app.get("/logout", function(req, res){
  res.redirect("/");
});

app.listen(5000, function(){
  console.log("Server started on port 5000");
});