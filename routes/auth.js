const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { body, validationResult } = require("express-validator");

const auth = (req, res, next) => {
    const raw = req.header("Authorization");
    const token = raw?.startsWith("Bearer ") ? raw.replace("Bearer ", "") : null;
    console.log(token);

    if (!token)
        return res.status(401).json({ error: "Access denied: missing token" });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = { id: decoded.id };
        next();
    } catch (error) {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
};

const validateSignup = [
    body("name")
        .isString().withMessage("Name must be a string")
        .notEmpty().withMessage("Name is required")
        .trim()
        .isLength({ min: 3, max: 30 }).withMessage("Name must be between 3 and 30 characters"),

    body("email")
        .isEmail().withMessage("Please provide a valid email")
        .normalizeEmail(),

    body("password")
        .isString().withMessage("Password must be a string")
        .notEmpty().withMessage("Password is required")
        .isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
];

const validateLogin = [
    body("name")
        .isString().withMessage("Name must be a string")
        .notEmpty().withMessage("Name is required"),

    body("email")
        .isString().withMessage("Email must be a string")
        .notEmpty().withMessage("Email is required"),

    body("password")
        .isString().withMessage("Password must be a string")
        .notEmpty().withMessage("Password is required"),
];

// Register Route
router.post("/register", validateSignup, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty())
            return res.status(400).json({ errors: errors.array() });
        const { name, email, password } = req.body;

        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: "User already exists" });
        }

        user = new User({ name, email, password });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        await user.save();
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.status(201).json({
            message: "User created successfully",
            token,
            user: {
                id: user._id
            },
        });
    } catch (err) {
        console.error(err.message);   // 👈 log actual error
        res.status(500).json({ msg: "Server error", error: err.message });
    }
});

//Login Route
router.post("/login", validateLogin, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty())
            return res.status(400).json({ errors: errors.array() });

        const { name, email, password } = req.body;

        const user = await User.findOne({ name });
        if (!user) return res.status(401).json({ error: "Invalid credentials" });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// for test purpose to check which users are there in db
router.get("/users", auth, async (req, res) => {
    try {
        const users = await User.find().select("-password"); // exclude password
        res.json(users);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ msg: "Server error", error: err.message });
    }
});





module.exports = router;
