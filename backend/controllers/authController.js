const db = require("../config/db");
const bcrypt = require("bcrypt");
const generateToken = require("../utils/jwt");

// Register
exports.register = async (req, res) => {
    try {
        const { fullname, email, password } = req.body;

        const hashPassword = await bcrypt.hash(password, 10);

        await db.query(
            "INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)",
            [fullname, email, hashPassword]
        );

        res.status(201).json({
            message: "Register Success"
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: "Server Error"
        });
    }
};

// Login
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        const [rows] = await db.query(
            "SELECT * FROM users WHERE email = ?",
            [email]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                message: "Email หรือ Password ไม่ถูกต้อง"
            });
        }

        const user = rows[0];

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({
                message: "Email หรือ Password ไม่ถูกต้อง"
            });
        }

        const token = generateToken(user);

        res.json({
            message: "Login Success",
            token,
            user: {
                user_id: user.user_id,
                fullname: user.fullname,
                email: user.email,
                role: user.role
            }
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: "Server Error"
        });
    }
};