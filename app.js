const express = require("express");
const app = express();

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.set("view engine", "ejs");

const secretkey = "aak@@@";

let users = [];

// Login page
app.get("/", (req, res) => {
    res.render("login", { msg: "" });
});

// Register page
app.get("/register", (req, res) => {
    res.render("register");
});

// Register user
app.post("/register", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({
        username: username,
        password: hashedPassword
    });

    res.redirect("/");
});

// Login user
app.post("/login", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const user = users.find(
        u => u.username === username
    );

    if (!user) {
        return res.render("login", {
            msg: "Invalid credentials"
        });
    }

    const isMatch = await bcrypt.compare(
        password,
        user.password
    );

    if (!isMatch) {
        return res.render("login", {
            msg: "Invalid credentials"
        });
    }

    const token = jwt.sign(
        {
            username: user.username
        },
        secretkey,
        {
            expiresIn: "1h"
        }
    );

    res.cookie("token", token);

    res.redirect("/profile");
});

// JWT middleware
function verifyToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect("/");
    }

    try {
        const decoded = jwt.verify(
            token,
            secretkey
        );

        req.user = decoded;

        next();
    } catch (err) {
        return res.send("Invalid Token");
    }
}

// Protected profile route
app.get("/profile", verifyToken, (req, res) => {
    res.render("profile", {
        user: req.user
    });
});

// Logout route
app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/");
});

app.listen(5000, () => {
    console.log("Server running on port 5000");
});