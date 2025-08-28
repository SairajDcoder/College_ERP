const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

// Register Route
router.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: "User already exists" });
        }

        user = new User({ name, email, password });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        await user.save();
        res.json({ msg: "User registered successfully" });
    } catch (err) {
        console.error(err.message);   // 👈 log actual error
        res.status(500).json({ msg: "Server error", error: err.message });
    }
});



module.exports = router;
