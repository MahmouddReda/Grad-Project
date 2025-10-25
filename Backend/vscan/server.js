const express = require("express");
const session = require("express-session");
const mysql = require("./mysql");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const { spawn } = require("child_process");

const app = express();
const path = require("path");

// Serve everything in the "public" folder
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }, // Set to true if using HTTPS
  })
);
app.use(
  express.static(
    path.join("E:/Study/Spring 2025/ECEN493 Graduation Project I/Web/Frontend")
  )
);
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
    req.session.user = {
      id: result.insertId,
      firstname: firstname,
      email: email,
    };
    res
      .status(201)
      .json({ message: "User created successfully", userId: result.insertId });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/api/user", (req, res) => {
  if (req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
});
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const [user] = await mysql.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    req.session.user = user;
    res.json({ message: "Login successful" });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      res.status(500).send("Error destroying session");
    } else {
      res.redirect("/");
    }
  });
});

//scanning
app.post("/scan", (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  // This command executes 'python scanner.py <the_url>'
  const pythonProcess = spawn("py", ["scanner.py", url]);

  let results = "";
  let errorOutput = "";

  // Capture the JSON output from the script
  pythonProcess.stdout.on("data", (data) => {
    results += data.toString();
  });

  // Capture any errors that the script prints
  pythonProcess.stderr.on("data", (data) => {
    errorOutput += data.toString();
  });

  // When the script is finished, send the results back to the frontend
  pythonProcess.on("close", (code) => {
    if (code !== 0 || errorOutput) {
      console.error(`Python script error output: ${errorOutput}`);
      return res
        .status(500)
        .json({ error: "The scanner failed to run.", details: errorOutput });
    }
    try {
      // Parse the JSON string we captured from the script
      const jsonData = JSON.parse(results);
      res.json(jsonData);
    } catch (e) {
      console.error("Error parsing JSON from Python script:", results);
      res.status(500).json({ error: "Could not parse the scan results." });
    }
  });
});

app.listen(8000, () => console.log("Server running on http://localhost:8000"));
