const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config(); // Load environment variables
var cors = require("cors");

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const mongoURI =
  "mongodb+srv://Arnav__O3:arnav03@cluster0.hhzdqdv.mongodb.net/SkillShare";
mongoose
  .connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected..."))
  .catch((err) => console.log("MongoDB connection error:", err));

const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  pswd: String,
  student: Boolean,
  age: { type: Number, max: 75 },
});

const User = mongoose.model("User", UserSchema);

function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Failed to authenticate token" });
    }

    req.user = decoded;
    next();
  });
}

app.get("/dashboard", authenticateToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.email} to the dashboard!` });
});

app.get("/users", (req, res) => {
  User.find({})
    .then((user) => res.json(user))
    .catch((err) => res.status(400).json("Error: " + err));
});

app.post("/login", (req, res) => {
  const { email, pswd } = req.body;

  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        return res.status(400).json({ message: "Invalid email or password" });
      }

      bcrypt.compare(pswd, user.pswd, (err, isMatch) => {
        if (err)
          return res.status(500).json({ message: "Error comparing passwords" });
        if (!isMatch) {
          return res.status(400).json({ message: "Invalid email or password" });
        }

        const token = jwt.sign(
          { id: user._id, email: user.email, username: user.username },
          process.env.SECRET_KEY,
          { expiresIn: "1h" }
        );

        res.json({ message: "Login successful", token });
      });
    })
    .catch((err) =>
      res.status(500).json({ message: "Server error", details: err })
    );
});

app.post("/signup", (req, res) => {
  const { username, email, pswd, student, age } = req.body;

  User.findOne({ email: email })
    .then((user) => {
      if (user) {
        return res.status(409).json({ message: "Email already exists" });
      } else {
        bcrypt.hash(pswd, 10, (err, hashedPassword) => {
          if (err)
            return res.status(500).json({ error: "Error hashing password" });

          const newUser = new User({
            username,
            email,
            pswd: hashedPassword,
            student,
            age,
          });

          newUser
            .save()
            .then((savedUser) =>
              res
                .status(201)
                .json({ message: "Signup successful", user: savedUser })
            )
            .catch((err) =>
              res.status(500).json({ error: "Error saving user", details: err })
            );
        });
      }
    })
    .catch((err) =>
      res.status(500).json({ error: "Server error", details: err })
    );
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
