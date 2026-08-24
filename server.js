"use strict";

/*
===========================================================
 N10 SERVER
 Express + PostgreSQL
 Register / Login / JWT / Access Keys
 Duplicate Discord ID protection
===========================================================
*/

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

/* =========================================================
   CONFIG
========================================================= */

const app = express();

const PORT = Number(process.env.PORT) || 3000;

const DATABASE_URL = process.env.DATABASE_URL;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "CHANGE_THIS_SECRET_IN_RENDER";

const NODE_ENV = process.env.NODE_ENV || "production";

if (!DATABASE_URL) {
  console.error("❌ DATABASE_URL is missing.");
  process.exit(1);
}

/* =========================================================
   POSTGRESQL
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl:
    process.env.PGSSLMODE === "disable"
      ? false
      : {
          rejectUnauthorized: false,
        },

  max: 10,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000,
});

/* PostgreSQL connection errors must NEVER crash the server. */
pool.on("error", (err) => {
  console.error("❌ Unexpected PostgreSQL pool error:");
  console.error(err);
});

/* =========================================================
   EXPRESS
========================================================= */

app.set("trust proxy", 1);

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

app.use(
  cors({
    origin: true,
    credentials: true,
    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Access-Key",
    ],
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

/* =========================================================
   HELPERS
========================================================= */

function cleanString(value) {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value).trim();
}

function normalizeDiscordId(value) {
  return cleanString(value).replace(/\s+/g, "");
}

function isValidDiscordId(id) {
  /*
   Discord snowflakes are numeric strings.
   We accept 15-25 digits to avoid unnecessarily
   rejecting valid IDs.
  */
  return /^\d{15,25}$/.test(id);
}

function isValidPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 6 &&
    password.length <= 200
  );
}

function createToken(account) {
  return jwt.sign(
    {
      sub: String(account.id),
      discord_id: String(account.discord_id),
    },
    JWT_SECRET,
    {
      expiresIn: "30d",
    }
  );
}

function publicAccount(account) {
  return {
    id: account.id,
    discord_id: account.discord_id,
    username: account.username || null,
    created_at: account.created_at,
    updated_at: account.updated_at,
  };
}

function getBearerToken(req) {
  const header = req.headers.authorization;

  if (!header) {
    return null;
  }

  if (!header.toLowerCase().startsWith("bearer ")) {
    return null;
  }

  return header.slice(7).trim();
}

async function authenticate(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        error: "UNAUTHORIZED",
        message: "Authentication token is required.",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      `
      SELECT
        id,
        discord_id,
        username,
        created_at,
        updated_at
      FROM accounts
      WHERE id = $1
      LIMIT 1
      `,
      [decoded.sub]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: "ACCOUNT_NOT_FOUND",
        message: "Account no longer exists.",
      });
    }

    req.account = result.rows[0];

    next();
  } catch (error) {
    console.error("Authentication error:", error);

    return res.status(401).json({
      success: false,
      error: "INVALID_TOKEN",
      message: "Invalid or expired authentication token.",
    });
  }
}

/* =========================================================
   ACCESS KEY
========================================================= */

function getConfiguredAccessKeys() {
  const raw = process.env.ACCESS_KEYS || "";

  return raw
    .split(",")
    .map((key) => key.trim())
    .filter(Boolean);
}

async function validateAccessKey(accessKey) {
  const key = cleanString(accessKey);

  if (!key) {
    return false;
  }

  /*
   First check environment variable:
   ACCESS_KEYS=KEY1,KEY2,KEY3
  */

  const envKeys = getConfiguredAccessKeys();

  if (envKeys.includes(key)) {
    return true;
  }

  /*
   Then check PostgreSQL access_keys table.
  */

  try {
    const result = await pool.query(
      `
      SELECT id
      FROM access_keys
      WHERE key_value = $1
        AND active = TRUE
      LIMIT 1
      `,
      [key]
    );

    return result.rows.length > 0;
  } catch (error) {
    console.error("Access key validation error:", error);

    return false;
  }
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {
  console.log("⏳ Connecting to PostgreSQL...");

  await pool.query("SELECT 1");

  console.log("✅ PostgreSQL connected.");

  /*
   Accounts
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id BIGSERIAL PRIMARY KEY,

      discord_id VARCHAR(32) NOT NULL,

      username VARCHAR(100),

      password_hash TEXT NOT NULL,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      CONSTRAINT accounts_discord_id_key
        UNIQUE (discord_id)
    );
  `);

  /*
   Access keys
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_keys (
      id BIGSERIAL PRIMARY KEY,

      key_value TEXT NOT NULL UNIQUE,

      active BOOLEAN NOT NULL DEFAULT TRUE,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  /*
   Sessions table
   Not required for JWT, but useful if you later
   need server-side session management.
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS login_logs (
      id BIGSERIAL PRIMARY KEY,

      account_id BIGINT,

      discord_id VARCHAR(32),

      success BOOLEAN NOT NULL DEFAULT FALSE,

      ip_address TEXT,

      user_agent TEXT,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  /*
   Helpful index.
  */

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_accounts_discord_id
    ON accounts(discord_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_login_logs_account_id
    ON login_logs(account_id);
  `);

  console.log("✅ Database initialized.");
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "N10 Server",
    status: "online",
    environment: NODE_ENV,
    time: new Date().toISOString(),
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.status(200).json({
      success: true,
      status: "healthy",
      database: "connected",
      time: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Health check failed:", error);

    res.status(503).json({
      success: false,
      status: "unhealthy",
      database: "disconnected",
    });
  }
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.status(200).json({
      success: true,
      status: "healthy",
      database: "connected",
    });
  } catch (error) {
    console.error("API health check failed:", error);

    res.status(503).json({
      success: false,
      status: "unhealthy",
      database: "disconnected",
    });
  }
});

/* =========================================================
   REGISTER
========================================================= */

async function registerHandler(req, res) {
  try {
    /*
     Accept multiple possible frontend field names.
    */

    const discordId = normalizeDiscordId(
      req.body.discordId ||
        req.body.discord_id ||
        req.body.discordID ||
        req.body.userId ||
        req.body.user_id
    );

    const password = cleanString(
      req.body.password ||
        req.body.pass ||
        req.body.password1
    );

    const confirmPassword = cleanString(
      req.body.confirmPassword ||
        req.body.confirm_password ||
        req.body.password2 ||
        req.body.confirmPass
    );

    const accessKey = cleanString(
      req.body.accessKey ||
        req.body.access_key ||
        req.body.key ||
        req.headers["x-access-key"]
    );

    const username = cleanString(
      req.body.username ||
        req.body.name ||
        req.body.displayName
    );

    /* -----------------------------------------------
       Validation
    ----------------------------------------------- */

    if (!discordId) {
      return res.status(400).json({
        success: false,
        error: "DISCORD_ID_REQUIRED",
        message: "Discord ID is required.",
      });
    }

    if (!isValidDiscordId(discordId)) {
      return res.status(400).json({
        success: false,
        error: "INVALID_DISCORD_ID",
        message: "Invalid Discord ID.",
      });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({
        success: false,
        error: "INVALID_PASSWORD",
        message:
          "Password must contain at least 6 characters.",
      });
    }

    if (
      confirmPassword &&
      password !== confirmPassword
    ) {
      return res.status(400).json({
        success: false,
        error: "PASSWORD_MISMATCH",
        message: "Passwords do not match.",
      });
    }

    /*
     Access key is required.
    */

    const accessKeyValid =
      await validateAccessKey(accessKey);

    if (!accessKeyValid) {
      return res.status(403).json({
        success: false,
        error: "INVALID_ACCESS_KEY",
        message: "Invalid or inactive Access Key.",
      });
    }

    /* -----------------------------------------------
       IMPORTANT:
       Check existing account BEFORE INSERT.
       This avoids the exact problem visible
       in your Render logs.
    ----------------------------------------------- */

    const existing = await pool.query(
      `
      SELECT
        id,
        discord_id,
        username,
        created_at,
        updated_at
      FROM accounts
      WHERE discord_id = $1
      LIMIT 1
      `,
      [discordId]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: "DISCORD_ALREADY_REGISTERED",
        message:
          "This Discord account is already registered.",
        account: publicAccount(existing.rows[0]),
      });
    }

    /* -----------------------------------------------
       Hash password
    ----------------------------------------------- */

    const passwordHash =
      await bcrypt.hash(password, 12);

    /*
     IMPORTANT:
     ON CONFLICT DO NOTHING gives us a second
     protection against race conditions.

     Example:
     Two registration requests arrive at the
     exact same millisecond with the same Discord ID.
    */

    const inserted = await pool.query(
      `
      INSERT INTO accounts (
        discord_id,
        username,
        password_hash
      )
      VALUES ($1, $2, $3)
      ON CONFLICT (discord_id)
      DO NOTHING
      RETURNING
        id,
        discord_id,
        username,
        created_at,
        updated_at
      `,
      [
        discordId,
        username || null,
        passwordHash,
      ]
    );

    /*
     If nothing was inserted, another request registered
     this Discord ID first.
    */

    if (inserted.rows.length === 0) {
      const alreadyExists = await pool.query(
        `
        SELECT
          id,
          discord_id,
          username,
          created_at,
          updated_at
        FROM accounts
        WHERE discord_id = $1
        LIMIT 1
        `,
        [discordId]
      );

      return res.status(409).json({
        success: false,
        error: "DISCORD_ALREADY_REGISTERED",
        message:
          "This Discord account is already registered.",
        account:
          alreadyExists.rows.length > 0
            ? publicAccount(alreadyExists.rows[0])
            : null,
      });
    }

    const account = inserted.rows[0];

    const token = createToken(account);

    console.log(
      `✅ New account registered: ${discordId}`
    );

    return res.status(201).json({
      success: true,
      message: "Registration successful.",
      token,
      account: publicAccount(account),
    });
  } catch (error) {
    /*
     PostgreSQL duplicate key protection.
     This specifically handles:
     23505
     accounts_discord_id_key
    */

    if (error && error.code === "23505") {
      console.error(
        "⚠️ Duplicate registration prevented:",
        error.detail || error.message
      );

      return res.status(409).json({
        success: false,
        error: "DISCORD_ALREADY_REGISTERED",
        message:
          "This Discord account is already registered.",
      });
    }

    console.error("❌ Register error:", error);

    return res.status(500).json({
      success: false,
      error: "REGISTER_FAILED",
      message:
        "Registration failed. Please try again.",
    });
  }
}

/*
 Support both:
 POST /register
 POST /api/register
*/

app.post("/register", registerHandler);
app.post("/api/register", registerHandler);

/* =========================================================
   LOGIN
========================================================= */

async function loginHandler(req, res) {
  try {
    const discordId = normalizeDiscordId(
      req.body.discordId ||
        req.body.discord_id ||
        req.body.discordID ||
        req.body.userId ||
        req.body.user_id
    );

    const password = cleanString(
      req.body.password ||
        req.body.pass
    );

    if (!discordId || !isValidDiscordId(discordId)) {
      return res.status(400).json({
        success: false,
        error: "INVALID_DISCORD_ID",
        message: "Invalid Discord ID.",
      });
    }

    if (!password) {
      return res.status(400).json({
        success: false,
        error: "PASSWORD_REQUIRED",
        message: "Password is required.",
      });
    }

    const result = await pool.query(
      `
      SELECT
        id,
        discord_id,
        username,
        password_hash,
        created_at,
        updated_at
      FROM accounts
      WHERE discord_id = $1
      LIMIT 1
      `,
      [discordId]
    );

    if (result.rows.length === 0) {
      await pool.query(
        `
        INSERT INTO login_logs (
          discord_id,
          success,
          ip_address,
          user_agent
        )
        VALUES ($1, FALSE, $2, $3)
        `,
        [
          discordId,
          req.ip || null,
          req.headers["user-agent"] || null,
        ]
      );

      return res.status(401).json({
        success: false,
        error: "INVALID_CREDENTIALS",
        message: "Discord ID or password is incorrect.",
      });
    }

    const account = result.rows[0];

    const passwordCorrect =
      await bcrypt.compare(
        password,
        account.password_hash
      );

    if (!passwordCorrect) {
      await pool.query(
        `
        INSERT INTO login_logs (
          account_id,
          discord_id,
          success,
          ip_address,
          user_agent
        )
        VALUES ($1, $2, FALSE, $3, $4)
        `,
        [
          account.id,
          account.discord_id,
          req.ip || null,
          req.headers["user-agent"] || null,
        ]
      );

      return res.status(401).json({
        success: false,
        error: "INVALID_CREDENTIALS",
        message: "Discord ID or password is incorrect.",
      });
    }

    /*
     Successful login.
    */

    await pool.query(
      `
      INSERT INTO login_logs (
        account_id,
        discord_id,
        success,
        ip_address,
        user_agent
      )
      VALUES ($1, $2, TRUE, $3, $4)
      `,
      [
        account.id,
        account.discord_id,
        req.ip || null,
        req.headers["user-agent"] || null,
      ]
    );

    const token = createToken(account);

    console.log(
      `✅ Login successful: ${discordId}`
    );

    return res.status(200).json({
      success: true,
      message: "Login successful.",
      token,
      account: publicAccount(account),
    });
  } catch (error) {
    console.error("❌ Login error:", error);

    return res.status(500).json({
      success: false,
      error: "LOGIN_FAILED",
      message: "Login failed. Please try again.",
    });
  }
}

app.post("/login", loginHandler);
app.post("/api/login", loginHandler);

/* =========================================================
   CURRENT USER
========================================================= */

async function meHandler(req, res) {
  try {
    return res.status(200).json({
      success: true,
      account: publicAccount(req.account),
    });
  } catch (error) {
    console.error("❌ /me error:", error);

    return res.status(500).json({
      success: false,
      error: "ME_FAILED",
      message: "Unable to load account.",
    });
  }
}

app.get("/me", authenticate, meHandler);
app.get("/api/me", authenticate, meHandler);

/* =========================================================
   CHECK DISCORD ID
========================================================= */

async function checkDiscordHandler(req, res) {
  try {
    const discordId = normalizeDiscordId(
      req.body.discordId ||
        req.body.discord_id ||
        req.query.discordId ||
        req.query.discord_id
    );

    if (!discordId || !isValidDiscordId(discordId)) {
      return res.status(400).json({
        success: false,
        error: "INVALID_DISCORD_ID",
        message: "Invalid Discord ID.",
      });
    }

    const result = await pool.query(
      `
      SELECT id
      FROM accounts
      WHERE discord_id = $1
      LIMIT 1
      `,
      [discordId]
    );

    return res.status(200).json({
      success: true,
      registered: result.rows.length > 0,
    });
  } catch (error) {
    console.error(
      "❌ Discord check error:",
      error
    );

    return res.status(500).json({
      success: false,
      error: "CHECK_FAILED",
      message: "Unable to check Discord account.",
    });
  }
}

app.get("/check-discord", checkDiscordHandler);
app.post("/check-discord", checkDiscordHandler);

app.get(
  "/api/check-discord",
  checkDiscordHandler
);

app.post(
  "/api/check-discord",
  checkDiscordHandler
);

/* =========================================================
   ACCESS KEY CHECK
========================================================= */

async function checkAccessKeyHandler(req, res) {
  try {
    const accessKey = cleanString(
      req.body.accessKey ||
        req.body.access_key ||
        req.body.key ||
        req.query.accessKey ||
        req.query.access_key ||
        req.headers["x-access-key"]
    );

    if (!accessKey) {
      return res.status(400).json({
        success: false,
        error: "ACCESS_KEY_REQUIRED",
        message: "Access Key is required.",
      });
    }

    const valid =
      await validateAccessKey(accessKey);

    return res.status(200).json({
      success: true,
      valid,
    });
  } catch (error) {
    console.error(
      "❌ Access key check error:",
      error
    );

    return res.status(500).json({
      success: false,
      error: "ACCESS_KEY_CHECK_FAILED",
      message: "Unable to check Access Key.",
    });
  }
}

app.get(
  "/check-access-key",
  checkAccessKeyHandler
);

app.post(
  "/check-access-key",
  checkAccessKeyHandler
);

app.get(
  "/api/check-access-key",
  checkAccessKeyHandler
);

app.post(
  "/api/check-access-key",
  checkAccessKeyHandler
);

/* =========================================================
   LOGOUT
========================================================= */

function logoutHandler(req, res) {
  /*
   JWT is stateless.

   The frontend should remove the token.
   This endpoint exists for compatibility.
  */

  return res.status(200).json({
    success: true,
    message: "Logged out successfully.",
  });
}

app.post("/logout", logoutHandler);
app.post("/api/logout", logoutHandler);

/* =========================================================
   ADMIN / DATABASE INFO
========================================================= */

/*
   This endpoint intentionally does NOT expose database
   credentials or private information.
*/

app.get("/api/status", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT COUNT(*)::INTEGER AS accounts
      FROM accounts
    `);

    return res.json({
      success: true,
      status: "online",
      accounts: result.rows[0].accounts,
      uptime: process.uptime(),
      node: process.version,
      time: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Status error:", error);

    return res.status(503).json({
      success: false,
      status: "database_error",
    });
  }
});

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    error: "NOT_FOUND",
    message: "Endpoint not found.",
    path: req.originalUrl,
  });
});

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("❌ GLOBAL ERROR:");

  console.error(error);

  /*
   PostgreSQL duplicate key.
   This is the exact error shown in your screenshots.
  */

  if (error && error.code === "23505") {
    return res.status(409).json({
      success: false,
      error: "DUPLICATE_VALUE",
      message:
        "The requested value already exists.",
    });
  }

  /*
   Invalid JSON.
  */

  if (
    error instanceof SyntaxError &&
    error.status === 400 &&
    error.type === "entity.parse.failed"
  ) {
    return res.status(400).json({
      success: false,
      error: "INVALID_JSON",
      message: "Invalid JSON request.",
    });
  }

  return res.status(500).json({
    success: false,
    error: "INTERNAL_SERVER_ERROR",
    message: "Internal server error.",
  });
});

/* =========================================================
   START SERVER
========================================================= */

let server = null;

async function startServer() {
  try {
    await initializeDatabase();

    server = app.listen(PORT, "0.0.0.0", () => {
      console.log("");
      console.log("==========================================");
      console.log("       N10 SERVER STARTED");
      console.log("==========================================");
      console.log(`PORT: ${PORT}`);
      console.log(`ENV:  ${NODE_ENV}`);
      console.log("DATABASE: PostgreSQL");
      console.log("STATUS: ONLINE");
      console.log("==========================================");
      console.log("");
    });
  } catch (error) {
    console.error("");
    console.error("❌ SERVER START FAILED");
    console.error(error);
    console.error("");

    /*
     Do not keep a broken server running.
    */

    process.exit(1);
  }
}

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

async function shutdown(signal) {
  console.log(
    `\n⚠️ Received ${signal}. Shutting down...`
  );

  try {
    if (server) {
      await new Promise((resolve) => {
        server.close(resolve);
      });
    }

    await pool.end();

    console.log("✅ Server stopped cleanly.");

    process.exit(0);
  } catch (error) {
    console.error(
      "❌ Shutdown error:",
      error
    );

    process.exit(1);
  }
}

process.on("SIGTERM", () => {
  shutdown("SIGTERM");
});

process.on("SIGINT", () => {
  shutdown("SIGINT");
});

/* =========================================================
   UNHANDLED ERRORS
========================================================= */

process.on("unhandledRejection", (reason) => {
  console.error(
    "❌ UNHANDLED PROMISE REJECTION:"
  );

  console.error(reason);

  /*
   Do NOT automatically kill the server.
  */
});

process.on("uncaughtException", (error) => {
  console.error(
    "❌ UNCAUGHT EXCEPTION:"
  );

  console.error(error);

  /*
   Do not silently continue if Node itself is
   in an unsafe state.
   Attempt graceful shutdown.
  */

  shutdown("uncaughtException");
});

/* =========================================================
   RUN
========================================================= */

startServer();
