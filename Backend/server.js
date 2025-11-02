const express = require("express");
const mysql = require("./mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");

const app = express();

app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.post("/signin", async (req, res) => {
  const { firstname, lastname, email, password, confirmPassword } = req.body;

  if (!firstname || !lastname || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Passwords do not match" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await mysql.query(
      "INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)",
      [firstname, lastname, email, hashedPassword]
    );
    res
      .status(201)
      .json({ message: "User created successfully", userId: result.insertId });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
