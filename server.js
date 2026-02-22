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
  }),
);
app.use(express.static(path.join(__dirname, "Frontend")));
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
      [firstname, lastname, email, hashedPassword],
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
// History Endpoint
app.get("/api/history", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const rows = await mysql.query(
      "SELECT * FROM scans WHERE user_id = ? ORDER BY scan_date DESC",
      [req.session.user.id],
    );
    res.json(rows);
  } catch (error) {
    console.error("Error fetching history:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Manual Save Endpoint (for Mock Mode)
app.post("/api/save_scan", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const { target, vulnerabilities } = req.body;

  try {
    const vulnCount = vulnerabilities ? vulnerabilities.length : 0;
    const vulnTypes = vulnerabilities
      ? [...new Set(vulnerabilities.map((v) => v.type))].join(", ")
      : "";

    await mysql.query(
      "INSERT INTO scans (user_id, target_url, vuln_count, vuln_types) VALUES (?, ?, ?, ?)",
      [req.session.user.id, target, vulnCount, vulnTypes],
    );
    res.json({ message: "Scan saved" });
  } catch (error) {
    console.error("Error saving manual scan:", error);
    res.status(500).json({ error: "Database error" });
  }
});

// scanning
app.post("/scan", (req, res) => {
  let { url, scannerType } = req.body;
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  // Normalize frontend value if needed
  if (scannerType === "automated") {
    scannerType = "classic";
  }

  // Choose the script based on selection
  let scriptPath = "./Scanner/mainscanner.py";
  if (scannerType === "ml") {
    scriptPath = "./Scanner/ml_scanner.py";
  }

  // This command executes 'python scanner.py <the_url>'
  const args = [scriptPath, url];

  // Handle Selection Flags
  const { runSql, runXss } = req.body;
  if (scannerType === "ml") {
    if (runSql && runXss) {
      args.push("--ml");
    } else if (runSql && !runXss) {
      args.push("--ml-sqli-only");
    } else if (!runSql && runXss) {
      args.push("--ml-xss-only");
    }
  } else if (scannerType === "classic") {
    if (runSql && runXss) {
      args.push("--classic");
    } else if (runSql && !runXss) {
      args.push("--classic-sqli-only");
    } else if (!runSql && runXss) {
      args.push("--classic-xss-only");
    } else {
      return res
        .status(400)
        .json({ error: "Please select at least one scan type." });
    }
  }

  const pythonProcess = spawn("python", args);

  let results = "";
  let errorOutput = "";
  let isProcessComplete = false;

  // Capture the JSON output from the script
  pythonProcess.stdout.on("data", (data) => {
    if (data.toString().includes("PROCESS_COMPLETE")) {
      isProcessComplete = true;
    }

    if (isProcessComplete) {
      results += data.toString();
      results = results.replace("PROCESS_COMPLETE", "");
    }

    console.log("DEBUG DATA", data.toString());
  });

  // Capture any errors that the script prints
  pythonProcess.stderr.on("data", (data) => {
    if (data.toString().includes("PROCESS_COMPLETE")) {
      isProcessComplete = true;
    }

    if (isProcessComplete) {
      errorOutput += data.toString();
      errorOutput = errorOutput.replace("PROCESS_COMPLETE", "");
    }

    console.error(data.toString());
  });

  // When the script is finished, send the results back to the frontend
  pythonProcess.on("close", async (code) => {
    if (code !== 0 || errorOutput) {
      return res
        .status(500)
        .json({ error: "The scanner failed to run.", details: errorOutput });
    }
    try {
      // Parse the JSON string we captured from the script
      const jsonData = JSON.parse(results);

      // SAVE TO DB IF LOGGED IN
      if (req.session.user) {
        console.log(
          "Attempting to save scan for User ID:",
          req.session.user.id,
        );
        const vulnCount = jsonData.vulnerabilities
          ? jsonData.vulnerabilities.length
          : 0;
        const vulnTypes = jsonData.vulnerabilities
          ? [...new Set(jsonData.vulnerabilities.map((v) => v.type))].join(", ")
          : "";

        try {
          await mysql.query(
            "INSERT INTO scans (user_id, target_url, vuln_count, vuln_types) VALUES (?, ?, ?, ?)",
            [req.session.user.id, jsonData.target, vulnCount, vulnTypes],
          );
          console.log("Scan saved successfully.");
        } catch (dbErr) {
          console.error("Database Save Error:", dbErr);
        }
      } else {
        console.log("Scan finished but user is NOT logged in. Skipping save.");
      }

      res.json(jsonData);
    } catch (e) {
      const fs = require("fs");
      fs.writeFileSync("./error.txt", results);

      console.error("JSON Parse Error. Raw Output was:", results);
      res.status(500).json({ error: "Invalid JSON from scanner" });
    }
  });
});

app.listen(8000, () => console.log("Server running on http://localhost:8000"));
