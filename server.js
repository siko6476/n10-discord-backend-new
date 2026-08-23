"use strict";

/*
========================================================
 N10 SERVER MENA
 Backend كامل
========================================================

- Discord OAuth2
- OAuth State protection
- PostgreSQL
- Access Keys
- Register
- Login
- Sessions 30 days
- Password hashing
- CORS
- Health Check
- Logout
- Database migration
========================================================
*/

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

/*
========================================================
 ENV
========================================================
*/

const PORT = Number(process.env.PORT || 3000);

const FRONTEND_URL = (
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io"
).replace(/\/+$/, "");

const DISCORD_CLIENT_ID =
  process.env.DISCORD_CLIENT_ID || "";

const DISCORD_CLIENT_SECRET =
  process.env.DISCORD_CLIENT_SECRET || "";

const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI ||
  "https://n10-discord-backend-new.onrender.com/auth/discord/callback";

const DATABASE_URL =
  process.env.DATABASE_URL || "";

const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET ||
  DISCORD_CLIENT_SECRET;

const SESSION_DAYS = 30;

/*
========================================================
 ENV CHECK
========================================================
*/

const missingEnv = [];

if (!DATABASE_URL) {
  missingEnv.push("DATABASE_URL");
}

if (!DISCORD_CLIENT_ID) {
  missingEnv.push("DISCORD_CLIENT_ID");
}

if (!DISCORD_CLIENT_SECRET) {
  missingEnv.push("DISCORD_CLIENT_SECRET");
}

if (!OAUTH_STATE_SECRET) {
  missingEnv.push("OAUTH_STATE_SECRET");
}

if (missingEnv.length > 0) {
  console.error(
    "❌ Missing environment variables:",
    missingEnv.join(", ")
  );
}

/*
========================================================
 POSTGRESQL
========================================================
*/

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl:
    process.env.NODE_ENV === "production"
      ? {
          rejectUnauthorized: false
        }
      : false,

  max: 10,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000
});

/*
========================================================
 EXPRESS
========================================================
*/

app.disable("x-powered-by");

/*
========================================================
 CORS
========================================================
*/

app.use(
  cors({
    origin: FRONTEND_URL,
    methods: [
      "GET",
      "POST",
      "OPTIONS"
    ],
    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ],
    credentials: false
  })
);

/*
========================================================
 BODY
========================================================
*/

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb"
  })
);

/*
========================================================
 HELPERS
========================================================
*/

function sendError(
  res,
  status,
  message
) {
  return res.status(status).json({
    success: false,
    message
  });
}

/*
========================================================
 USERNAME
========================================================
*/

function cleanUsername(username) {
  return String(username || "").trim();
}

function normalizeUsername(username) {
  return cleanUsername(username).toLowerCase();
}

function validUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,24}$/.test(
    username
  );
}

/*
========================================================
 PASSWORD
========================================================
*/

function validPassword(password) {
  if (typeof password !== "string") {
    return false;
  }

  const bytes =
    Buffer.byteLength(password, "utf8");

  return bytes >= 6 && bytes <= 72;
}

/*
========================================================
 ACCESS KEY
========================================================
*/

function validAccessKey(key) {
  return (
    typeof key === "string" &&
    /^N10-[A-Za-z0-9]+$/.test(key)
  );
}

function generateAccessKey() {
  return (
    "N10-" +
    crypto
      .randomBytes(18)
      .toString("hex")
  );
}

/*
========================================================
 SESSION
========================================================
*/

function generateSessionToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

/*
========================================================
 OAUTH STATE
========================================================

State مربوط بالمتصفح عن طريق Cookie.
هذا أفضل من State عشوائي وحده.
========================================================
*/

function generateOAuthState() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

function signOAuthState(state) {
  return crypto
    .createHmac(
      "sha256",
      OAUTH_STATE_SECRET
    )
    .update(state)
    .digest("hex");
}

function createOAuthState() {
  const state =
    generateOAuthState();

  const signature =
    signOAuthState(state);

  return {
    state,
    value:
      `${state}.${signature}`
  };
}

function verifyOAuthState(value) {
  if (
    !value ||
    typeof value !== "string"
  ) {
    return false;
  }

  const parts =
    value.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const [
    state,
    signature
  ] = parts;

  if (!state || !signature) {
    return false;
  }

  const expected =
    signOAuthState(state);

  if (
    signature.length !==
    expected.length
  ) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch {
    return false;
  }
}

/*
========================================================
 COOKIE HELPERS
========================================================
*/

function setOAuthCookie(res, state) {
  const isProduction =
    process.env.NODE_ENV === "production";

  const cookie =
    [
      `n10_oauth_state=${encodeURIComponent(state)}`,
      "HttpOnly",
      "Path=/auth/discord",
      "SameSite=Lax",
      isProduction ? "Secure" : ""
    ]
      .filter(Boolean)
      .join("; ");

  res.setHeader(
    "Set-Cookie",
    cookie
  );
}

function clearOAuthCookie(res) {
  const isProduction =
    process.env.NODE_ENV === "production";

  const cookie =
    [
      "n10_oauth_state=",
      "HttpOnly",
      "Path=/auth/discord",
      "SameSite=Lax",
      "Max-Age=0",
      isProduction ? "Secure" : ""
    ]
      .filter(Boolean)
      .join("; ");

  res.setHeader(
    "Set-Cookie",
    cookie
  );
}

function getCookie(req, name) {
  const header =
    req.headers.cookie || "";

  const parts =
    header.split(";");

  for (const part of parts) {
    const [key, ...rest] =
      part.trim().split("=");

    if (key === name) {
      return decodeURIComponent(
        rest.join("=")
      );
    }
  }

  return null;
}

/*
========================================================
 FRONTEND REDIRECT
========================================================
*/

function frontendRedirect(params = {}) {
  const url =
    new URL(FRONTEND_URL);

  for (
    const [key, value]
    of Object.entries(params)
  ) {
    if (
      value !== undefined &&
      value !== null
    ) {
      url.searchParams.set(
        key,
        String(value)
      );
    }
  }

  return url.toString();
}

/*
========================================================
 DATABASE INITIALIZATION
========================================================
*/

async function initDatabase() {
  if (!DATABASE_URL) {
    throw new Error(
      "DATABASE_URL غير موجود."
    );
  }

  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    /*
    ====================================================
    USERS
    ====================================================
    */

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,

        username VARCHAR(24) NOT NULL,

        username_normalized VARCHAR(24)
          UNIQUE NOT NULL,

        password_hash TEXT NOT NULL,

        access_key TEXT
          UNIQUE NOT NULL,

        discord_id TEXT
          UNIQUE,

        created_at TIMESTAMP
          DEFAULT CURRENT_TIMESTAMP
      )
    `);

    /*
    ====================================================
    ACCESS KEYS
    ====================================================
    */

    await client.query(`
      CREATE TABLE IF NOT EXISTS access_keys (
        id SERIAL PRIMARY KEY,

        access_key TEXT
          UNIQUE NOT NULL,

        discord_id TEXT,

        used BOOLEAN
          NOT NULL DEFAULT FALSE,

        used_by INTEGER,

        created_at TIMESTAMP
          DEFAULT CURRENT_TIMESTAMP,

        used_at TIMESTAMP
      )
    `);

    /*
    ====================================================
    SESSIONS
    ====================================================
    */

    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,

        token TEXT
          UNIQUE NOT NULL,

        user_id INTEGER
          NOT NULL,

        created_at TIMESTAMP
          DEFAULT CURRENT_TIMESTAMP,

        expires_at TIMESTAMP
      )
    `);

    /*
    ====================================================
    MIGRATION
    ====================================================
    */

    await client.query(`
      ALTER TABLE sessions
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP
    `);

    await client.query(`
      UPDATE sessions
      SET expires_at =
        COALESCE(
          expires_at,
          created_at +
          INTERVAL '30 days'
        )
      WHERE expires_at IS NULL
    `);

    /*
    ====================================================
    INDEXES
    ====================================================
    */

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_access_keys_discord
      ON access_keys(discord_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_sessions_user
      ON sessions(user_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_sessions_expires
      ON sessions(expires_at)
    `);

    await client.query("COMMIT");

    console.log(
      "✅ PostgreSQL database جاهزة."
    );
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(
      "❌ Database initialization error:",
      error
    );

    throw error;
  } finally {
    client.release();
  }
}

/*
========================================================
 HOME
========================================================
*/

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "N10 SERVER MENA",
    status: "online",
    time: new Date().toISOString()
  });
});

/*
========================================================
 HEALTH
========================================================
*/

app.get(
  "/health",
  async (req, res) => {
    try {
      await pool.query(
        "SELECT 1"
      );

      return res.json({
        success: true,
        status: "online",
        database: "connected"
      });
    } catch (error) {
      console.error(
        "❌ Health error:",
        error
      );

      return res.status(500).json({
        success: false,
        status: "online",
        database: "error"
      });
    }
  }
);

/*
========================================================
 DISCORD AUTH
========================================================
*/

app.get(
  "/auth/discord",
  (req, res) => {
    try {
      if (
        !DISCORD_CLIENT_ID ||
        !DISCORD_CLIENT_SECRET ||
        !OAUTH_STATE_SECRET
      ) {
        return sendError(
          res,
          500,
          "إعدادات Discord ناقصة في Render."
        );
      }

      const oauth =
        createOAuthState();

      /*
      نخزن State في Cookie
      */

      setOAuthCookie(
        res,
        oauth.value
      );

      /*
      Discord OAuth URL
      */

      const params =
        new URLSearchParams({
          client_id:
            DISCORD_CLIENT_ID,

          response_type:
            "code",

          redirect_uri:
            DISCORD_REDIRECT_URI,

          scope:
            "identify",

          state:
            oauth.value
        });

      const discordURL =
        "https://discord.com/oauth2/authorize?" +
        params.toString();

      return res.redirect(
        discordURL
      );
    } catch (error) {
      console.error(
        "❌ Discord auth error:",
        error
      );

      return sendError(
        res,
        500,
        "تعذر بدء تسجيل الدخول عبر Discord."
      );
    }
  }
);

/*
========================================================
 DISCORD CALLBACK
========================================================
*/

app.get(
  "/auth/discord/callback",
  async (req, res) => {
    try {
      const code =
        String(
          req.query.code || ""
        );

      const returnedState =
        String(
          req.query.state || ""
        );

      const savedState =
        getCookie(
          req,
          "n10_oauth_state"
        );

      /*
      ==================================================
      تحقق State
      ==================================================
      */

      if (
        !returnedState ||
        !savedState ||
        returnedState !== savedState ||
        !verifyOAuthState(
          returnedState
        )
      ) {
        console.error(
          "❌ OAuth State mismatch."
        );

        clearOAuthCookie(res);

        return res.redirect(
          frontendRedirect({
            error:
              "invalid_oauth_state"
          })
        );
      }

      clearOAuthCookie(res);

      /*
      ==================================================
      Discord cancel
      ==================================================
      */

      if (!code) {
        return res.redirect(
          frontendRedirect({
            error:
              "discord_cancelled"
          })
        );
      }

      /*
      ==================================================
      TOKEN
      ==================================================
      */

      const tokenResponse =
        await fetch(
          "https://discord.com/api/v10/oauth2/token",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded"
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
                  DISCORD_REDIRECT_URI
              }).toString()
          }
        );

      const tokenData =
        await tokenResponse.json();

      if (
        !tokenResponse.ok ||
        !tokenData.access_token
      ) {
        console.error(
          "❌ Discord token error:",
          tokenData
        );

        return res.redirect(
          frontendRedirect({
            error:
              "discord_token_error"
          })
        );
      }

      /*
      ==================================================
      DISCORD USER
      ==================================================
      */

      const userResponse =
        await fetch(
          "https://discord.com/api/v10/users/@me",
          {
            method: "GET",

            headers: {
              Authorization:
                `Bearer ${tokenData.access_token}`
            }
          }
        );

      const discordUser =
        await userResponse.json();

      if (
        !userResponse.ok ||
        !discordUser.id
      ) {
        console.error(
          "❌ Discord user error:",
          discordUser
        );

        return res.redirect(
          frontendRedirect({
            error:
              "discord_user_error"
          })
        );
      }

      const discordId =
        String(
          discordUser.id
        );

      console.log(
        "✅ Discord user:",
        discordId
      );

      /*
      ==================================================
      EXISTING USER
      ==================================================
      */

      const existingUser =
        await pool.query(
          `
          SELECT
            id,
            username,
            access_key
          FROM users
          WHERE discord_id = $1
          LIMIT 1
          `,
          [discordId]
        );

      if (
        existingUser.rows.length > 0
      ) {
        const user =
          existingUser.rows[0];

        console.log(
          "✅ Existing N10 user:",
          user.username
        );

        return res.redirect(
          frontendRedirect({
            accessKey:
              user.access_key
          })
        );
      }

      /*
      ==================================================
      CHECK OLD UNUSED KEY
      ==================================================
      */

      let accessKey = null;

      const oldKey =
        await pool.query(
          `
          SELECT
            access_key
          FROM access_keys
          WHERE discord_id = $1
            AND used = FALSE
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [discordId]
        );

      if (
        oldKey.rows.length > 0
      ) {
        accessKey =
          oldKey.rows[0].access_key;

        console.log(
          "✅ Existing unused Access Key found."
        );
      }

      /*
      ==================================================
      CREATE NEW KEY
      ==================================================
      */

      if (!accessKey) {
        for (
          let i = 0;
          i < 10;
          i++
        ) {
          const candidate =
            generateAccessKey();

          try {
            await pool.query(
              `
              INSERT INTO access_keys
                (
                  access_key,
                  discord_id,
                  used
                )
              VALUES
                ($1, $2, FALSE)
              `,
              [
                candidate,
                discordId
              ]
            );

            accessKey =
              candidate;

            console.log(
              "✅ New Access Key created."
            );

            break;
          } catch (error) {
            if (
              error.code === "23505"
            ) {
              continue;
            }

            throw error;
          }
        }
      }

      /*
      ==================================================
      FINAL CHECK
      ==================================================
      */

      if (!accessKey) {
        console.error(
          "❌ Access Key generation failed."
        );

        return res.redirect(
          frontendRedirect({
            error:
              "key_generation_failed"
          })
        );
      }

      /*
      ==================================================
      REDIRECT FRONTEND
      ==================================================
      */

      console.log(
        "➡️ Redirecting to:",
        FRONTEND_URL
      );

      return res.redirect(
        frontendRedirect({
          accessKey
        })
      );
    } catch (error) {
      console.error(
        "❌ Discord callback error:",
        error
      );

      return res.redirect(
        frontendRedirect({
          error:
            "discord_error"
        })
      );
    }
  }
);

/*
========================================================
 REGISTER
========================================================
*/

app.post(
  "/api/register",
  async (req, res) => {
    const {
      username,
      password,
      confirmPassword,
      accessKey
    } = req.body;

    const cleanName =
      cleanUsername(username);

    const normalizedName =
      normalizeUsername(username);

    const key =
      String(
        accessKey || ""
      ).trim();

    /*
    ====================================================
    VALIDATION
    ====================================================
    */

    if (
      !cleanName ||
      !password ||
      !confirmPassword ||
      !key
    ) {
      return sendError(
        res,
        400,
        "الرجاء ملء جميع الخانات."
      );
    }

    if (
      !validUsername(
        cleanName
      )
    ) {
      return sendError(
        res,
        400,
        "اسم المستخدم يجب أن يكون بين 3 و24 حرفاً."
      );
    }

    if (
      !validPassword(
        password
      )
    ) {
      return sendError(
        res,
        400,
        "كلمة المرور يجب أن تكون بين 6 و72 بايت."
      );
    }

    if (
      password !==
      confirmPassword
    ) {
      return sendError(
        res,
        400,
        "كلمتا المرور غير متطابقتين."
      );
    }

    if (
      !validAccessKey(key)
    ) {
      return sendError(
        res,
        400,
        "Access Key غير صالح."
      );
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      /*
      ==================================================
      USERNAME
      ==================================================
      */

      const usernameExists =
        await client.query(
          `
          SELECT id
          FROM users
          WHERE username_normalized = $1
          LIMIT 1
          `,
          [normalizedName]
        );

      if (
        usernameExists.rows.length > 0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return sendError(
          res,
          409,
          "اسم المستخدم مستعمل من قبل."
        );
      }

      /*
      ==================================================
      ACCESS KEY
      ==================================================
      */

      const keyResult =
        await client.query(
          `
          SELECT
            id,
            access_key,
            discord_id,
            used
          FROM access_keys
          WHERE access_key = $1
          FOR UPDATE
          `,
          [key]
        );

      if (
        keyResult.rows.length === 0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return sendError(
          res,
          400,
          "Access Key غير موجود."
        );
      }

      const keyRow =
        keyResult.rows[0];

      /*
      ==================================================
      KEY ALREADY USED
      ==================================================
      */

      if (
        keyRow.used === true
      ) {
        await client.query(
          "ROLLBACK"
        );

        return sendError(
          res,
          400,
          "Access Key مستعمل من قبل."
        );
      }

      /*
      ==================================================
      PASSWORD HASH
      ==================================================
      */

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      /*
      ==================================================
      CREATE USER
      ==================================================
      */

      const userResult =
        await client.query(
          `
          INSERT INTO users
            (
              username,
              username_normalized,
              password_hash,
              access_key,
              discord_id
            )
          VALUES
            ($1, $2, $3, $4, $5)
          RETURNING
            id,
            username,
            access_key,
            discord_id,
            created_at
          `,
          [
            cleanName,
            normalizedName,
            passwordHash,
            keyRow.access_key,
            keyRow.discord_id
          ]
        );

      const user =
        userResult.rows[0];

      /*
      ==================================================
      MARK KEY USED
      ==================================================
      */

      await client.query(
        `
        UPDATE access_keys
        SET
          used = TRUE,
          used_by = $1,
          used_at = CURRENT_TIMESTAMP
        WHERE id = $2
        `,
        [
          user.id,
          keyRow.id
        ]
      );

      await client.query(
        "COMMIT"
      );

      console.log(
        "✅ User registered:",
        user.username
      );

      return res.status(201).json({
        success: true,

        message:
          "تم إنشاء الحساب بنجاح.",

        user: {
          id: user.id,
          username: user.username,
          accessKey:
            user.access_key,
          discordId:
            user.discord_id,
          createdAt:
            user.created_at
        }
      });
    } catch (error) {
      await client.query(
        "ROLLBACK"
      );

      console.error(
        "❌ Register error:",
        error
      );

      if (
        error.code === "23505"
      ) {
        return sendError(
          res,
          409,
          "اسم المستخدم أو Access Key مستعمل من قبل."
        );
      }

      return sendError(
        res,
        500,
        "حدث خطأ أثناء إنشاء الحساب."
      );
    } finally {
      client.release();
    }
  }
);

/*
========================================================
 LOGIN
========================================================
*/

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const {
        username,
        password
      } = req.body;

      const normalizedName =
        normalizeUsername(
          username
        );

      if (
        !normalizedName ||
        !password
      ) {
        return sendError(
          res,
          400,
          "الرجاء إدخال اسم المستخدم وكلمة المرور."
        );
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            username,
            password_hash,
            access_key,
            discord_id,
            created_at
          FROM users
          WHERE username_normalized = $1
          LIMIT 1
          `,
          [normalizedName]
        );

      if (
        result.rows.length === 0
      ) {
        return sendError(
          res,
          401,
          "اسم المستخدم أو كلمة المرور غير صحيحة."
        );
      }

      const user =
        result.rows[0];

      const passwordOK =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!passwordOK) {
        return sendError(
          res,
          401,
          "اسم المستخدم أو كلمة المرور غير صحيحة."
        );
      }

      /*
      ==================================================
      SESSION
      ==================================================
      */

      const token =
        generateSessionToken();

      const expiresAt =
        new Date(
          Date.now() +
          SESSION_DAYS *
            24 *
            60 *
            60 *
            1000
        );

      await pool.query(
        `
        INSERT INTO sessions
          (
            token,
            user_id,
            expires_at
          )
        VALUES
          ($1, $2, $3)
        `,
        [
          token,
          user.id,
          expiresAt
        ]
      );

      return res.json({
        success: true,

        message:
          "تم تسجيل الدخول بنجاح.",

        token,

        accessKey:
          user.access_key,

        user: {
          id: user.id,
          username:
            user.username,
          accessKey:
            user.access_key,
          discordId:
            user.discord_id,
          createdAt:
            user.created_at
        }
      });
    } catch (error) {
      console.error(
        "❌ Login error:",
        error
      );

      return sendError(
        res,
        500,
        "حدث خطأ أثناء تسجيل الدخول."
      );
    }
  }
);

/*
========================================================
 GET USER
========================================================
*/

app.get(
  "/api/user",
  async (req, res) => {
    try {
      const auth =
        req.headers.authorization || "";

      if (
        !auth.startsWith(
          "Bearer "
        )
      ) {
        return sendError(
          res,
          401,
          "غير مصرح."
        );
      }

      const token =
        auth
          .substring(7)
          .trim();

      if (!token) {
        return sendError(
          res,
          401,
          "Session غير صالحة."
        );
      }

      const result =
        await pool.query(
          `
          SELECT
            u.id,
            u.username,
            u.access_key,
            u.discord_id,
            u.created_at
          FROM sessions s
          JOIN users u
            ON u.id = s.user_id
          WHERE
            s.token = $1
            AND s.expires_at > CURRENT_TIMESTAMP
          LIMIT 1
          `,
          [token]
        );

      if (
        result.rows.length === 0
      ) {
        /*
        حذف Session منتهية
        */

        await pool.query(
          `
          DELETE FROM sessions
          WHERE token = $1
          `,
          [token]
        );

        return sendError(
          res,
          401,
          "Session منتهية أو غير صالحة."
        );
      }

      const user =
        result.rows[0];

      return res.json({
        success: true,

        user: {
          id: user.id,
          username:
            user.username,
          accessKey:
            user.access_key,
          discordId:
            user.discord_id,
          createdAt:
            user.created_at
        }
      });
    } catch (error) {
      console.error(
        "❌ Get user error:",
        error
      );

      return sendError(
        res,
        500,
        "حدث خطأ في السيرفر."
      );
    }
  }
);

/*
========================================================
 LOGOUT
========================================================
*/

app.post(
  "/api/logout",
  async (req, res) => {
    try {
      const auth =
        req.headers.authorization || "";

      if (
        auth.startsWith(
          "Bearer "
        )
      ) {
        const token =
          auth
            .substring(7)
            .trim();

        if (token) {
          await pool.query(
            `
            DELETE FROM sessions
            WHERE token = $1
            `,
            [token]
          );
        }
      }

      return res.json({
        success: true,
        message:
          "تم تسجيل الخروج."
      });
    } catch (error) {
      console.error(
        "❌ Logout error:",
        error
      );

      return sendError(
        res,
        500,
        "حدث خطأ أثناء تسجيل الخروج."
      );
    }
  }
);

/*
========================================================
 CLEAN EXPIRED SESSIONS
========================================================
*/

async function cleanExpiredSessions() {
  try {
    const result =
      await pool.query(
        `
        DELETE FROM sessions
        WHERE expires_at <= CURRENT_TIMESTAMP
        `
      );

    if (
      result.rowCount > 0
    ) {
      console.log(
        `🧹 Deleted ${result.rowCount} expired sessions.`
      );
    }
  } catch (error) {
    console.error(
      "❌ Session cleanup error:",
      error
    );
  }
}

/*
========================================================
 404
========================================================
*/

app.use(
  (req, res) => {
    return res.status(404).json({
      success: false,
      message:
        "المسار غير موجود.",
      path: req.path
    });
  }
);

/*
========================================================
 GLOBAL ERROR
========================================================
*/

app.use(
  (error, req, res, next) => {
    console.error(
      "❌ Unhandled error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "حدث خطأ داخلي في السيرفر."
    });
  }
);

/*
========================================================
 START SERVER
========================================================
*/

async function startServer() {
  try {
    if (
      missingEnv.length > 0
    ) {
      throw new Error(
        `Environment variables ناقصة: ${missingEnv.join(", ")}`
      );
    }

    await initDatabase();

    await cleanExpiredSessions();

    setInterval(
      cleanExpiredSessions,
      60 * 60 * 1000
    );

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          "========================================"
        );

        console.log(
          "🚀 N10 SERVER MENA ONLINE"
        );

        console.log(
          `🌐 Port: ${PORT}`
        );

        console.log(
          `🌐 Frontend: ${FRONTEND_URL}`
        );

        console.log(
          `🔗 Discord Callback: ${DISCORD_REDIRECT_URI}`
        );

        console.log(
          "🗄️ PostgreSQL: CONNECTED"
        );

        console.log(
          "🔐 OAuth State: ENABLED"
        );

        console.log(
          "⏱️ Sessions: 30 DAYS"
        );

        console.log(
          "========================================"
        );
      }
    );
  } catch (error) {
    console.error(
      "========================================"
    );

    console.error(
      "❌ SERVER STARTUP FAILED"
    );

    console.error(
      error.message
    );

    console.error(
      "========================================"
    );

    process.exit(1);
  }
}

startServer();
