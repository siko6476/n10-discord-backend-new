"use strict";

/*
===========================================================
 N10 SERVER - FIXED VERSION
 Express + PostgreSQL + JWT + Discord OAuth
 Register / Login / Access Key
 Duplicate Discord ID protection
 Render compatible
===========================================================
*/

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

/* =========================================================
   CONFIG
========================================================= */

const app = express();

const PORT = Number(process.env.PORT) || 3000;

const DATABASE_URL = process.env.DATABASE_URL;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "N10_CHANGE_THIS_SECRET_2026";

const NODE_ENV =
  process.env.NODE_ENV || "production";

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io/N10-SERVER-MENA";

const DISCORD_CLIENT_ID =
  process.env.DISCORD_CLIENT_ID || "";

const DISCORD_CLIENT_SECRET =
  process.env.DISCORD_CLIENT_SECRET || "";

const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI ||
  "";

if (!DATABASE_URL) {
  console.error("❌ DATABASE_URL غير موجود في Render.");
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

pool.on("error", (error) => {
  console.error("❌ PostgreSQL pool error:");
  console.error(error);
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

app.use(
  express.json({
    limit: "2mb",
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "2mb",
  })
);

/* =========================================================
   HELPERS
========================================================= */

function cleanString(value) {
  if (
    value === undefined ||
    value === null
  ) {
    return "";
  }

  return String(value).trim();
}

function normalizeDiscordId(value) {
  return cleanString(value)
    .replace(/\s+/g, "");
}

function isValidDiscordId(id) {
  return /^\d{15,25}$/.test(id);
}

function isValidPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 6 &&
    password.length <= 200
  );
}

function publicAccount(account) {
  return {
    id: account.id,
    discord_id: account.discord_id,
    username: account.username || null,
    access_key: account.access_key || null,
    created_at: account.created_at,
    updated_at: account.updated_at,
  };
}

/* =========================================================
   JWT
========================================================= */

function createToken(account) {
  return jwt.sign(
    {
      sub: String(account.id),

      discord_id: String(
        account.discord_id
      ),
    },

    JWT_SECRET,

    {
      expiresIn: "30d",
    }
  );
}

function getBearerToken(req) {
  const header =
    req.headers.authorization;

  if (!header) {
    return null;
  }

  if (
    !header
      .toLowerCase()
      .startsWith("bearer ")
  ) {
    return null;
  }

  return header
    .slice(7)
    .trim();
}

/* =========================================================
   AUTHENTICATION
========================================================= */

async function authenticate(
  req,
  res,
  next
) {
  try {
    const token =
      getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        error: "UNAUTHORIZED",
        message:
          "Authentication token is required.",
      });
    }

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    const result =
      await pool.query(
        `
        SELECT
          id,
          discord_id,
          username,
          access_key,
          created_at,
          updated_at
        FROM accounts
        WHERE id = $1
        LIMIT 1
        `,
        [decoded.sub]
      );

    if (
      result.rows.length === 0
    ) {
      return res.status(401).json({
        success: false,
        error: "ACCOUNT_NOT_FOUND",
        message:
          "Account no longer exists.",
      });
    }

    req.account =
      result.rows[0];

    next();
  } catch (error) {
    console.error(
      "❌ Authentication error:",
      error
    );

    return res.status(401).json({
      success: false,
      error: "INVALID_TOKEN",
      message:
        "Invalid or expired token.",
    });
  }
}

/* =========================================================
   ACCESS KEY
========================================================= */

/*
   Access Key is now OPTIONAL.

   If the user does not enter one,
   the server generates one automatically.
*/

function generateAccessKey() {
  const part1 =
    crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase();

  const part2 =
    crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase();

  const part3 =
    crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase();

  return `N10-${part1}-${part2}-${part3}`;
}

async function createUniqueAccessKey() {
  for (let attempt = 0; attempt < 10; attempt++) {
    const key =
      generateAccessKey();

    const result =
      await pool.query(
        `
        SELECT id
        FROM accounts
        WHERE access_key = $1
        LIMIT 1
        `,
        [key]
      );

    if (
      result.rows.length === 0
    ) {
      return key;
    }
  }

  throw new Error(
    "Unable to generate unique Access Key."
  );
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {
  console.log(
    "⏳ Connecting to PostgreSQL..."
  );

  await pool.query(
    "SELECT 1"
  );

  console.log(
    "✅ PostgreSQL connected."
  );

  /*
   Create accounts table if it does not exist.
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id BIGSERIAL PRIMARY KEY,

      discord_id VARCHAR(32) NOT NULL,

      username VARCHAR(100),

      password_hash TEXT NOT NULL,

      access_key TEXT,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );
  `);

  /*
   IMPORTANT:
   Do not recreate the old constraint.
   Create a unique index instead.
   This protects Discord IDs from duplicates.
  */

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
      accounts_discord_id_unique_idx
    ON accounts(discord_id);
  `);

  /*
   Unique Access Key index.
  */

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
      accounts_access_key_unique_idx
    ON accounts(access_key)
    WHERE access_key IS NOT NULL;
  `);

  /*
   Access keys table.
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_keys (
      id BIGSERIAL PRIMARY KEY,

      key_value TEXT NOT NULL UNIQUE,

      active BOOLEAN
        NOT NULL DEFAULT TRUE,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );
  `);

  /*
   Login logs.
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS login_logs (
      id BIGSERIAL PRIMARY KEY,

      account_id BIGINT,

      discord_id VARCHAR(32),

      success BOOLEAN
        NOT NULL DEFAULT FALSE,

      ip_address TEXT,

      user_agent TEXT,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    );
  `);

  /*
   Helpful indexes.
  */

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      idx_accounts_discord_id
    ON accounts(discord_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      idx_login_logs_account_id
    ON login_logs(account_id);
  `);

  /*
   Add access_key column to an existing
   old database if necessary.
  */

  await pool.query(`
    ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS access_key TEXT;
  `);

  /*
   Give old accounts an Access Key.
  */

  const oldAccounts =
    await pool.query(`
      SELECT id
      FROM accounts
      WHERE access_key IS NULL
    `);

  for (
    const account of oldAccounts.rows
  ) {
    const key =
      await createUniqueAccessKey();

    await pool.query(
      `
      UPDATE accounts
      SET
        access_key = $1,
        updated_at = NOW()
      WHERE id = $2
      `,
      [
        key,
        account.id,
      ]
    );

    console.log(
      `🔑 Access Key generated for account ${account.id}`
    );
  }

  console.log(
    "✅ Database initialized."
  );
}

/* =========================================================
   ROOT
========================================================= */

app.get(
  "/",
  (req, res) => {
    res.json({
      success: true,

      name: "N10 Server",

      status: "online",

      environment:
        NODE_ENV,

      time:
        new Date().toISOString(),
    });
  }
);

/* =========================================================
   HEALTH
========================================================= */

async function healthHandler(
  req,
  res
) {
  try {
    await pool.query(
      "SELECT 1"
    );

    return res.status(200).json({
      success: true,
      status: "healthy",
      database: "connected",
      time:
        new Date().toISOString(),
    });
  } catch (error) {
    console.error(
      "❌ Health error:",
      error
    );

    return res.status(503).json({
      success: false,
      status: "unhealthy",
      database: "disconnected",
    });
  }
}

app.get(
  "/health",
  healthHandler
);

app.get(
  "/api/health",
  healthHandler
);

/* =========================================================
   REGISTER
========================================================= */

async function registerHandler(
  req,
  res
) {
  try {
    const discordId =
      normalizeDiscordId(
        req.body.discordId ||
          req.body.discord_id ||
          req.body.discordID ||
          req.body.userId ||
          req.body.user_id
      );

    const password =
      cleanString(
        req.body.password ||
          req.body.pass ||
          req.body.password1
      );

    const confirmPassword =
      cleanString(
        req.body.confirmPassword ||
          req.body.confirm_password ||
          req.body.password2 ||
          req.body.confirmPass
      );

    const username =
      cleanString(
        req.body.username ||
          req.body.name ||
          req.body.displayName
      );

    /*
     Access Key is OPTIONAL.
     We accept it if the frontend sends one.
    */

    const requestedAccessKey =
      cleanString(
        req.body.accessKey ||
          req.body.access_key ||
          req.body.key ||
          req.headers["x-access-key"]
      );

    /* -----------------------------------------------
       Validate Discord ID
    ----------------------------------------------- */

    if (!discordId) {
      return res.status(400).json({
        success: false,
        error: "DISCORD_ID_REQUIRED",
        message:
          "Discord ID is required.",
      });
    }

    if (
      !isValidDiscordId(
        discordId
      )
    ) {
      return res.status(400).json({
        success: false,
        error: "INVALID_DISCORD_ID",
        message:
          "Invalid Discord ID.",
      });
    }

    /* -----------------------------------------------
       Validate password
    ----------------------------------------------- */

    if (
      !isValidPassword(
        password
      )
    ) {
      return res.status(400).json({
        success: false,
        error: "INVALID_PASSWORD",
        message:
          "Password must contain at least 6 characters.",
      });
    }

    if (
      confirmPassword &&
      password !==
        confirmPassword
    ) {
      return res.status(400).json({
        success: false,
        error: "PASSWORD_MISMATCH",
        message:
          "Passwords do not match.",
      });
    }

    /* -----------------------------------------------
       CHECK EXISTING ACCOUNT
    ----------------------------------------------- */

    const existing =
      await pool.query(
        `
        SELECT
          id,
          discord_id,
          username,
          access_key,
          created_at,
          updated_at
        FROM accounts
        WHERE discord_id = $1
        LIMIT 1
        `,
        [discordId]
      );

    if (
      existing.rows.length > 0
    ) {
      /*
       IMPORTANT:
       Do NOT try INSERT again.
       This fixes:
       accounts_discord_id_key
      */

      return res.status(409).json({
        success: false,
        error:
          "DISCORD_ALREADY_REGISTERED",

        message:
          "This Discord account is already registered.",

        account:
          publicAccount(
            existing.rows[0]
          ),
      });
    }

    /* -----------------------------------------------
       PASSWORD HASH
    ----------------------------------------------- */

    const passwordHash =
      await bcrypt.hash(
        password,
        12
      );

    /* -----------------------------------------------
       ACCESS KEY
    ----------------------------------------------- */

    let accessKey =
      requestedAccessKey;

    /*
     If no Access Key was entered,
     automatically create one.
    */

    if (!accessKey) {
      accessKey =
        await createUniqueAccessKey();
    }

    /* -----------------------------------------------
       INSERT
    ----------------------------------------------- */

    const inserted =
      await pool.query(
        `
        INSERT INTO accounts (
          discord_id,
          username,
          password_hash,
          access_key
        )
        VALUES (
          $1,
          $2,
          $3,
          $4
        )

        ON CONFLICT (discord_id)
        DO NOTHING

        RETURNING
          id,
          discord_id,
          username,
          access_key,
          created_at,
          updated_at
        `,
        [
          discordId,
          username || null,
          passwordHash,
          accessKey,
        ]
      );

    /*
     Race condition protection.
    */

    if (
      inserted.rows.length === 0
    ) {
      const duplicate =
        await pool.query(
          `
          SELECT
            id,
            discord_id,
            username,
            access_key,
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
        error:
          "DISCORD_ALREADY_REGISTERED",

        message:
          "This Discord account is already registered.",

        account:
          duplicate.rows.length
            ? publicAccount(
                duplicate.rows[0]
              )
            : null,
      });
    }

    const account =
      inserted.rows[0];

    /*
     Create JWT.
    */

    const token =
      createToken(account);

    console.log(
      `✅ REGISTER SUCCESS: ${discordId}`
    );

    return res.status(201).json({
      success: true,

      message:
        "Registration successful.",

      token,

      accessKey:
        account.access_key,

      access_key:
        account.access_key,

      account:
        publicAccount(account),
    });
  } catch (error) {
    /*
     Duplicate key protection.
    */

    if (
      error &&
      error.code === "23505"
    ) {
      console.error(
        "⚠️ Duplicate value prevented:",
        error.detail ||
          error.message
      );

      return res.status(409).json({
        success: false,

        error:
          "DISCORD_ALREADY_REGISTERED",

        message:
          "This Discord account is already registered.",
      });
    }

    console.error(
      "❌ REGISTER ERROR:",
      error
    );

    return res.status(500).json({
      success: false,

      error:
        "REGISTER_FAILED",

      message:
        "Registration failed. Please try again.",
    });
  }
}

app.post(
  "/register",
  registerHandler
);

app.post(
  "/api/register",
  registerHandler
);

/* =========================================================
   LOGIN
========================================================= */

async function loginHandler(
  req,
  res
) {
  try {
    const discordId =
      normalizeDiscordId(
        req.body.discordId ||
          req.body.discord_id ||
          req.body.discordID ||
          req.body.userId ||
          req.body.user_id
      );

    const password =
      cleanString(
        req.body.password ||
          req.body.pass
      );

    if (
      !discordId ||
      !isValidDiscordId(
        discordId
      )
    ) {
      return res.status(400).json({
        success: false,
        error:
          "INVALID_DISCORD_ID",
        message:
          "Invalid Discord ID.",
      });
    }

    if (!password) {
      return res.status(400).json({
        success: false,
        error:
          "PASSWORD_REQUIRED",
        message:
          "Password is required.",
      });
    }

    const result =
      await pool.query(
        `
        SELECT
          id,
          discord_id,
          username,
          password_hash,
          access_key,
          created_at,
          updated_at
        FROM accounts
        WHERE discord_id = $1
        LIMIT 1
        `,
        [discordId]
      );

    if (
      result.rows.length === 0
    ) {
      return res.status(401).json({
        success: false,
        error:
          "INVALID_CREDENTIALS",
        message:
          "Discord ID or password is incorrect.",
      });
    }

    const account =
      result.rows[0];

    const passwordCorrect =
      await bcrypt.compare(
        password,
        account.password_hash
      );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        error:
          "INVALID_CREDENTIALS",
        message:
          "Discord ID or password is incorrect.",
      });
    }

    /*
     If old account doesn't have Access Key,
     create one now.
    */

    if (
      !account.access_key
    ) {
      const key =
        await createUniqueAccessKey();

      await pool.query(
        `
        UPDATE accounts
        SET
          access_key = $1,
          updated_at = NOW()
        WHERE id = $2
        `,
        [
          key,
          account.id,
        ]
      );

      account.access_key =
        key;
    }

    /*
     Log successful login.
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
      VALUES (
        $1,
        $2,
        TRUE,
        $3,
        $4
      )
      `,
      [
        account.id,
        account.discord_id,
        req.ip || null,
        req.headers[
          "user-agent"
        ] || null,
      ]
    );

    const token =
      createToken(account);

    console.log(
      `✅ LOGIN SUCCESS: ${discordId}`
    );

    return res.status(200).json({
      success: true,

      message:
        "Login successful.",

      token,

      accessKey:
        account.access_key,

      access_key:
        account.access_key,

      account:
        publicAccount(account),
    });
  } catch (error) {
    console.error(
      "❌ LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      success: false,

      error:
        "LOGIN_FAILED",

      message:
        "Login failed. Please try again.",
    });
  }
}

app.post(
  "/login",
  loginHandler
);

app.post(
  "/api/login",
  loginHandler
);

/* =========================================================
   CURRENT USER
========================================================= */

async function meHandler(
  req,
  res
) {
  return res.status(200).json({
    success: true,

    account:
      publicAccount(
        req.account
      ),
  });
}

app.get(
  "/me",
  authenticate,
  meHandler
);

app.get(
  "/api/me",
  authenticate,
  meHandler
);

/* =========================================================
   CHECK DISCORD
========================================================= */

async function checkDiscordHandler(
  req,
  res
) {
  try {
    const discordId =
      normalizeDiscordId(
        req.body.discordId ||
          req.body.discord_id ||
          req.query.discordId ||
          req.query.discord_id
      );

    if (
      !discordId ||
      !isValidDiscordId(
        discordId
      )
    ) {
      return res.status(400).json({
        success: false,
        error:
          "INVALID_DISCORD_ID",
        message:
          "Invalid Discord ID.",
      });
    }

    const result =
      await pool.query(
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

      registered:
        result.rows.length > 0,
    });
  } catch (error) {
    console.error(
      "❌ CHECK DISCORD ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        "CHECK_FAILED",
      message:
        "Unable to check Discord account.",
    });
  }
}

app.get(
  "/check-discord",
  checkDiscordHandler
);

app.post(
  "/check-discord",
  checkDiscordHandler
);

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

async function checkAccessKeyHandler(
  req,
  res
) {
  try {
    const key =
      cleanString(
        req.body.accessKey ||
          req.body.access_key ||
          req.body.key ||
          req.query.accessKey ||
          req.query.access_key ||
          req.headers[
            "x-access-key"
          ]
      );

    /*
     Empty key is now allowed.
     This prevents the frontend from getting
     stuck just because Access Key is empty.
    */

    if (!key) {
      return res.status(200).json({
        success: true,
        valid: true,
        required: false,
        message:
          "Access Key is optional.",
      });
    }

    const result =
      await pool.query(
        `
        SELECT id
        FROM accounts
        WHERE access_key = $1
        LIMIT 1
        `,
        [key]
      );

    return res.status(200).json({
      success: true,

      valid:
        result.rows.length > 0,

      required: false,
    });
  } catch (error) {
    console.error(
      "❌ ACCESS KEY ERROR:",
      error
    );

    return res.status(500).json({
      success: false,

      error:
        "ACCESS_KEY_CHECK_FAILED",

      message:
        "Unable to check Access Key.",
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
   GENERATE ACCESS KEY
========================================================= */

async function generateAccessKeyHandler(
  req,
  res
) {
  try {
    const key =
      await createUniqueAccessKey();

    /*
     Save it in access_keys table too.
    */

    await pool.query(
      `
      INSERT INTO access_keys (
        key_value,
        active
      )
      VALUES ($1, TRUE)
      ON CONFLICT (key_value)
      DO NOTHING
      `,
      [key]
    );

    return res.status(201).json({
      success: true,

      accessKey: key,

      access_key: key,

      message:
        "Access Key generated.",
    });
  } catch (error) {
    console.error(
      "❌ GENERATE KEY ERROR:",
      error
    );

    return res.status(500).json({
      success: false,

      error:
        "ACCESS_KEY_GENERATION_FAILED",

      message:
        "Unable to generate Access Key.",
    });
  }
}

app.get(
  "/generate-access-key",
  generateAccessKeyHandler
);

app.post(
  "/generate-access-key",
  generateAccessKeyHandler
);

app.get(
  "/api/generate-access-key",
  generateAccessKeyHandler
);

app.post(
  "/api/generate-access-key",
  generateAccessKeyHandler
);

/* =========================================================
   DISCORD OAUTH
========================================================= */

/*
   This endpoint gives the frontend the Discord
   authorization URL.

   Required Render variables:

   DISCORD_CLIENT_ID
   DISCORD_CLIENT_SECRET
   DISCORD_REDIRECT_URI
*/

app.get(
  "/auth/discord",
  (req, res) => {
    try {
      if (
        !DISCORD_CLIENT_ID ||
        !DISCORD_REDIRECT_URI
      ) {
        return res.status(503).json({
          success: false,

          error:
            "DISCORD_NOT_CONFIGURED",

          message:
            "Discord OAuth is not configured on the server.",
        });
      }

      const params =
        new URLSearchParams({
          client_id:
            DISCORD_CLIENT_ID,

          redirect_uri:
            DISCORD_REDIRECT_URI,

          response_type:
            "code",

          scope:
            "identify",
        });

      const url =
        "https://discord.com/oauth2/authorize?" +
        params.toString();

      return res.json({
        success: true,

        url,
      });
    } catch (error) {
      console.error(
        "❌ Discord OAuth URL error:",
        error
      );

      return res.status(500).json({
        success: false,

        error:
          "DISCORD_OAUTH_ERROR",
      });
    }
  }
);

/* =========================================================
   DISCORD CALLBACK
========================================================= */

app.get(
  "/auth/discord/callback",
  async (req, res) => {
    try {
      const code =
        cleanString(
          req.query.code
        );

      const oauthError =
        cleanString(
          req.query.error
        );

      if (oauthError) {
        return res.redirect(
          `${FRONTEND_URL}/?discord_error=${encodeURIComponent(
            oauthError
          )}`
        );
      }

      if (!code) {
        return res.redirect(
          `${FRONTEND_URL}/?discord_error=missing_code`
        );
      }

      if (
        !DISCORD_CLIENT_ID ||
        !DISCORD_CLIENT_SECRET ||
        !DISCORD_REDIRECT_URI
      ) {
        return res.redirect(
          `${FRONTEND_URL}/?discord_error=server_not_configured`
        );
      }

      /*
       Exchange OAuth code for Discord token.
      */

      const tokenResponse =
        await fetch(
          "https://discord.com/api/oauth2/token",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded",
            },

            body:
              new URLSearchParams({
                client_id:
                  DISCORD_CLIENT_ID,

                client_secret:
                  DISCORD_CLIENT_SECRET,

                grant_type:
                  "authorization_code",

                code,

                redirect_uri:
                  DISCORD_REDIRECT_URI,
              }).toString(),
          }
        );

      if (
        !tokenResponse.ok
      ) {
        const text =
          await tokenResponse.text();

        console.error(
          "❌ Discord token error:",
          text
        );

        return res.redirect(
          `${FRONTEND_URL}/?discord_error=token_exchange_failed`
        );
      }

      const tokenData =
        await tokenResponse.json();

      /*
       Get Discord user.
      */

      const userResponse =
        await fetch(
          "https://discord.com/api/users/@me",
          {
            headers: {
              Authorization:
                `Bearer ${tokenData.access_token}`,
            },
          }
        );

      if (
        !userResponse.ok
      ) {
        const text =
          await userResponse.text();

        console.error(
          "❌ Discord user error:",
          text
        );

        return res.redirect(
          `${FRONTEND_URL}/?discord_error=user_fetch_failed`
        );
      }

      const discordUser =
        await userResponse.json();

      const discordId =
        normalizeDiscordId(
          discordUser.id
        );

      const username =
        cleanString(
          discordUser.global_name ||
            discordUser.username ||
            ""
        );

      if (
        !isValidDiscordId(
          discordId
        )
      ) {
        return res.redirect(
          `${FRONTEND_URL}/?discord_error=invalid_discord_id`
        );
      }

      /*
       Check if account exists.
      */

      let result =
        await pool.query(
          `
          SELECT
            id,
            discord_id,
            username,
            password_hash,
            access_key,
            created_at,
            updated_at
          FROM accounts
          WHERE discord_id = $1
          LIMIT 1
          `,
          [discordId]
        );

      let account;

      /*
       Existing account:
       Login automatically.
      */

      if (
        result.rows.length > 0
      ) {
        account =
          result.rows[0];

        if (
          !account.access_key
        ) {
          account.access_key =
            await createUniqueAccessKey();

          await pool.query(
            `
            UPDATE accounts
            SET
              access_key = $1,
              updated_at = NOW()
            WHERE id = $2
            `,
            [
              account.access_key,
              account.id,
            ]
          );
        }

        if (
          !account.username &&
          username
        ) {
          account.username =
            username;

          await pool.query(
            `
            UPDATE accounts
            SET
              username = $1,
              updated_at = NOW()
            WHERE id = $2
            `,
            [
              username,
              account.id,
            ]
          );
        }
      } else {
        /*
         New Discord account.

         We create a random password hash because
         Discord OAuth does not need the normal password.
        */

        const randomPassword =
          crypto.randomBytes(
            32
          ).toString("hex");

        const passwordHash =
          await bcrypt.hash(
            randomPassword,
            12
          );

        const accessKey =
          await createUniqueAccessKey();

        const inserted =
          await pool.query(
            `
            INSERT INTO accounts (
              discord_id,
              username,
              password_hash,
              access_key
            )
            VALUES (
              $1,
              $2,
              $3,
              $4
            )

            ON CONFLICT (discord_id)
            DO NOTHING

            RETURNING
              id,
              discord_id,
              username,
              password_hash,
              access_key,
              created_at,
              updated_at
            `,
            [
              discordId,
              username ||
                null,
              passwordHash,
              accessKey,
            ]
          );

        /*
         Race condition:
         Someone registered the same Discord ID
         at exactly the same time.
        */

        if (
          inserted.rows.length === 0
        ) {
          const existingAccount =
            await pool.query(
              `
              SELECT
                id,
                discord_id,
                username,
                password_hash,
                access_key,
                created_at,
                updated_at
              FROM accounts
              WHERE discord_id = $1
              LIMIT 1
              `,
              [discordId]
            );

          if (
            existingAccount.rows.length === 0
          ) {
            return res.redirect(
              `${FRONTEND_URL}/?discord_error=registration_failed`
            );
          }

          account =
            existingAccount.rows[0];
        } else {
          account =
            inserted.rows[0];
        }
      }

      /*
       Create JWT.
      */

      const token =
        createToken(account);

      /*
       Redirect to frontend with token.

       The frontend can read:
       token
       discord_id
       access_key
      */

      const redirectParams =
        new URLSearchParams({
          token,

          discord_id:
            String(
              account.discord_id
            ),

          access_key:
            String(
              account.access_key || ""
            ),
        });

      return res.redirect(
        `${FRONTEND_URL}/?${redirectParams.toString()}`
      );
    } catch (error) {
      console.error(
        "❌ DISCORD CALLBACK ERROR:"
      );

      console.error(error);

      return res.redirect(
        `${FRONTEND_URL}/?discord_error=server_error`
      );
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/logout",
  (req, res) => {
    return res.json({
      success: true,

      message:
        "Logged out successfully.",
    });
  }
);

app.post(
  "/api/logout",
  (req, res) => {
    return res.json({
      success: true,

      message:
        "Logged out successfully.",
    });
  }
);

/* =========================================================
   STATUS
========================================================= */

app.get(
  "/api/status",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            COUNT(*)::INTEGER AS accounts
          FROM accounts
        `);

      return res.json({
        success: true,

        status:
          "online",

        accounts:
          result.rows[0]
            .accounts,

        uptime:
          process.uptime(),

        node:
          process.version,

        time:
          new Date().toISOString(),
      });
    } catch (error) {
      console.error(
        "❌ STATUS ERROR:",
        error
      );

      return res.status(503).json({
        success: false,

        status:
          "database_error",
      });
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use(
  (req, res) => {
    return res.status(404).json({
      success: false,

      error:
        "NOT_FOUND",

      message:
        "Endpoint not found.",

      path:
        req.originalUrl,
    });
  }
);

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "❌ GLOBAL ERROR:"
    );

    console.error(error);

    if (
      error &&
      error.code === "23505"
    ) {
      return res.status(409).json({
        success: false,

        error:
          "DUPLICATE_VALUE",

        message:
          "This value already exists.",
      });
    }

    if (
      error instanceof SyntaxError &&
      error.status === 400 &&
      error.type ===
        "entity.parse.failed"
    ) {
      return res.status(400).json({
        success: false,

        error:
          "INVALID_JSON",

        message:
          "Invalid JSON request.",
      });
    }

    return res.status(500).json({
      success: false,

      error:
        "INTERNAL_SERVER_ERROR",

      message:
        "Internal server error.",
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

let server = null;

async function startServer() {
  try {
    await initializeDatabase();

    server =
      app.listen(
        PORT,
        "0.0.0.0",
        () => {
          console.log("");
          console.log(
            "=========================================="
          );
          console.log(
            "          N10 SERVER STARTED"
          );
          console.log(
            "=========================================="
          );
          console.log(
            `PORT: ${PORT}`
          );
          console.log(
            `ENV: ${NODE_ENV}`
          );
          console.log(
            "DATABASE: PostgreSQL"
          );
          console.log(
            "DISCORD OAUTH: READY"
          );
          console.log(
            "STATUS: ONLINE"
          );
          console.log(
            "=========================================="
          );
          console.log("");
        }
      );
  } catch (error) {
    console.error("");
    console.error(
      "❌ SERVER START FAILED"
    );
    console.error(error);
    console.error("");

    process.exit(1);
  }
}

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

async function shutdown(
  signal
) {
  console.log(
    `\n⚠️ ${signal} received.`
  );

  try {
    if (server) {
      await new Promise(
        (resolve) => {
          server.close(
            resolve
          );
        }
      );
    }

    await pool.end();

    console.log(
      "✅ Server stopped cleanly."
    );

    process.exit(0);
  } catch (error) {
    console.error(
      "❌ Shutdown error:",
      error
    );

    process.exit(1);
  }
}

process.on(
  "SIGTERM",
  () => {
    shutdown(
      "SIGTERM"
    );
  }
);

process.on(
  "SIGINT",
  () => {
    shutdown(
      "SIGINT"
    );
  }
);

/* =========================================================
   UNHANDLED ERRORS
========================================================= */

process.on(
  "unhandledRejection",
  (reason) => {
    console.error(
      "❌ UNHANDLED PROMISE REJECTION:"
    );

    console.error(
      reason
    );
  }
);

process.on(
  "uncaughtException",
  (error) => {
    console.error(
      "❌ UNCAUGHT EXCEPTION:"
    );

    console.error(
      error
    );

    shutdown(
      "uncaughtException"
    );
  }
);

/* =========================================================
   RUN
========================================================= */

startServer();
