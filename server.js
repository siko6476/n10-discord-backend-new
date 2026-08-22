const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const crypto = require("crypto");
const { Pool } = require("pg");

require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not configured");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});


// ===============================
// إنشاء الجداول
// ===============================

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      username_lower TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS access_keys (
      access_key TEXT PRIMARY KEY,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      discord_id TEXT,
      discord_username TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      used_at TIMESTAMPTZ
    );
  `);

  console.log("Database initialized");
}


// ===============================
// الصفحة الرئيسية
// ===============================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "N10 Discord Backend is running!",
    version: "2.0.0"
  });
});


// ===============================
// حالة السيرفر
// ===============================

app.get("/api/status", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COUNT(*)::int AS count FROM users"
    );

    res.json({
      online: true,
      users: result.rows[0].count,
      time: new Date().toISOString()
    });

  } catch (error) {
    console.error("STATUS ERROR:", error);

    res.status(500).json({
      online: false,
      message: "Database error"
    });
  }
});


// ===============================
// إنشاء Access Key
// ===============================

app.post("/api/admin/create-key", async (req, res) => {
  try {
    const { adminKey, accessKey } = req.body;

    if (!process.env.ADMIN_KEY) {
      return res.status(500).json({
        success: false,
        message: "ADMIN_KEY is not configured"
      });
    }

    if (adminKey !== process.env.ADMIN_KEY) {
      return res.status(403).json({
        success: false,
        message: "Invalid admin key"
      });
    }

    const cleanAccessKey = String(accessKey || "").trim();

    if (cleanAccessKey.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Access key must contain at least 6 characters"
      });
    }

    const existing = await pool.query(
      "SELECT access_key FROM access_keys WHERE access_key = $1",
      [cleanAccessKey]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Access key already exists"
      });
    }

    await pool.query(
      `
      INSERT INTO access_keys
      (access_key, used, created_at)
      VALUES ($1, FALSE, NOW())
      `,
      [cleanAccessKey]
    );

    res.json({
      success: true,
      message: "Access key created",
      accessKey: cleanAccessKey
    });

  } catch (error) {
    console.error("CREATE KEY ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});


// ===============================
// تسجيل مستخدم جديد
// ===============================

app.post("/api/register", async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      username,
      password,
      confirmPassword,
      accessKey
    } = req.body;

    const cleanUsername = String(username || "").trim();
    const cleanAccessKey = String(accessKey || "").trim();

    if (
      !cleanUsername ||
      !password ||
      !confirmPassword ||
      !cleanAccessKey
    ) {
      return res.status(400).json({
        success: false,
        message: "All fields are required"
      });
    }

    if (cleanUsername.length < 3) {
      return res.status(400).json({
        success: false,
        message: "Username must contain at least 3 characters"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 6 characters"
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Passwords do not match"
      });
    }

    await client.query("BEGIN");

    // قفل Access Key أثناء التسجيل
    const keyResult = await client.query(
      `
      SELECT *
      FROM access_keys
      WHERE access_key = $1
      FOR UPDATE
      `,
      [cleanAccessKey]
    );

    if (keyResult.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(403).json({
        success: false,
        message: "Invalid access key"
      });
    }

    const keyInfo = keyResult.rows[0];

    if (keyInfo.used) {
      await client.query("ROLLBACK");

      return res.status(403).json({
        success: false,
        message: "This access key has already been used"
      });
    }

    const usernameLower = cleanUsername.toLowerCase();

    const existingUser = await client.query(
      `
      SELECT id
      FROM users
      WHERE username_lower = $1
      `,
      [usernameLower]
    );

    if (existingUser.rows.length > 0) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        success: false,
        message: "Username already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(
      password,
      12
    );

    const userId = crypto.randomUUID();

    await client.query(
      `
      INSERT INTO users
      (
        id,
        username,
        username_lower,
        password,
        created_at
      )
      VALUES ($1, $2, $3, $4, NOW())
      `,
      [
        userId,
        cleanUsername,
        usernameLower,
        hashedPassword
      ]
    );

    await client.query(
      `
      UPDATE access_keys
      SET
        used = TRUE,
        used_at = NOW()
      WHERE access_key = $1
      `,
      [cleanAccessKey]
    );

    await client.query("COMMIT");

    console.log(
      `Account created: ${cleanUsername}`
    );

    return res.status(201).json({
      success: true,
      message: "Account created successfully",
      user: {
        id: userId,
        username: cleanUsername
      }
    });

  } catch (error) {
    await client.query("ROLLBACK");

    console.error(
      "REGISTER ERROR:",
      error
    );

    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "Username already exists"
      });
    }

    return res.status(500).json({
      success: false,
      message: "Server error"
    });

  } finally {
    client.release();
  }
});


// ===============================
// تسجيل الدخول
// ===============================

app.post("/api/login", async (req, res) => {
  try {
    const {
      username,
      password
    } = req.body;

    const cleanUsername =
      String(username || "").trim();

    if (!cleanUsername || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    const usernameLower =
      cleanUsername.toLowerCase();

    const result = await pool.query(
      `
      SELECT
        id,
        username,
        password
      FROM users
      WHERE username_lower = $1
      LIMIT 1
      `,
      [usernameLower]
    );

    if (result.rows.length === 0) {
      console.log(
        `LOGIN: user not found -> ${cleanUsername}`
      );

      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    const user = result.rows[0];

    const passwordCorrect =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!passwordCorrect) {
      console.log(
        `LOGIN: wrong password -> ${cleanUsername}`
      );

      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    console.log(
      `LOGIN SUCCESS: ${user.username}`
    );

    return res.json({
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});


// ===============================
// Discord OAuth
// ===============================

app.get("/auth/discord", (req, res) => {
  if (!process.env.DISCORD_CLIENT_ID) {
    return res.status(500).send(
      "Discord Client ID is not configured"
    );
  }

  if (!process.env.DISCORD_REDIRECT_URI) {
    return res.status(500).send(
      "DISCORD_REDIRECT_URI is not configured"
    );
  }

  const params = new URLSearchParams({
    client_id:
      process.env.DISCORD_CLIENT_ID,

    redirect_uri:
      process.env.DISCORD_REDIRECT_URI,

    response_type: "code",

    scope: "identify email"
  });

  res.redirect(
    `https://discord.com/oauth2/authorize?${params.toString()}`
  );
});


// ===============================
// Discord OAuth Callback
// ===============================

app.get("/auth/discord/callback", async (req, res) => {
  try {
    const { code } = req.query;

    if (!code) {
      return res.status(400).json({
        success: false,
        message: "Authorization code is missing"
      });
    }

    if (
      !process.env.DISCORD_CLIENT_ID ||
      !process.env.DISCORD_CLIENT_SECRET ||
      !process.env.DISCORD_REDIRECT_URI
    ) {
      return res.status(500).json({
        success: false,
        message: "Discord environment variables are missing"
      });
    }

    const tokenResponse = await axios.post(
      "https://discord.com/api/oauth2/token",

      new URLSearchParams({
        client_id:
          process.env.DISCORD_CLIENT_ID,

        client_secret:
          process.env.DISCORD_CLIENT_SECRET,

        grant_type:
          "authorization_code",

        code,

        redirect_uri:
          process.env.DISCORD_REDIRECT_URI
      }).toString(),

      {
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        }
      }
    );

    const accessToken =
      tokenResponse.data.access_token;

    const userResponse = await axios.get(
      "https://discord.com/api/users/@me",
      {
        headers: {
          Authorization:
            `Bearer ${accessToken}`
        }
      }
    );

    const discordUser =
      userResponse.data;

    const accessKey =
      "N10-" +
      crypto.randomBytes(24).toString("hex");

    await pool.query(
      `
      INSERT INTO access_keys
      (
        access_key,
        used,
        discord_id,
        discord_username,
        created_at
      )
      VALUES ($1, FALSE, $2, $3, NOW())
      `,
      [
        accessKey,
        discordUser.id,
        discordUser.username
      ]
    );

    const FRONTEND_URL =
      process.env.FRONTEND_URL;

    if (!FRONTEND_URL) {
      return res.status(500).json({
        success: false,
        message: "FRONTEND_URL is not configured"
      });
    }

    res.redirect(
      `${FRONTEND_URL}?accessKey=${encodeURIComponent(accessKey)}`
    );

  } catch (error) {
    console.error(
      "Discord OAuth Error:",
      error.response?.data ||
      error.message
    );

    res.status(500).json({
      success: false,
      message: "Discord authentication failed"
    });
  }
});


// ===============================
// تشغيل السيرفر
// ===============================

async function startServer() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Server running on port ${PORT}`
        );
      }
    );

  } catch (error) {
    console.error(
      "SERVER START ERROR:",
      error
    );

    process.exit(1);
  }
}

startServer();
