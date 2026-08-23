"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

/* =====================================================
   CONFIG
===================================================== */

const PORT = Number(process.env.PORT || 3000);

const FRONTEND_URL = (
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io/N10-SERVER-MENA/"
).replace(/\/+$/, "");

const DISCORD_CLIENT_ID =
  process.env.DISCORD_CLIENT_ID;

const DISCORD_CLIENT_SECRET =
  process.env.DISCORD_CLIENT_SECRET;

const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI ||
  "https://n10-discord-backend-new.onrender.com/auth/discord/callback";

const DATABASE_URL =
  process.env.DATABASE_URL;

const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET ||
  DISCORD_CLIENT_SECRET;

const SESSION_DAYS = 30;

const SESSION_MS =
  SESSION_DAYS *
  24 *
  60 *
  60 *
  1000;

/* =====================================================
   ENV CHECK
===================================================== */

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

/* =====================================================
   DATABASE
===================================================== */

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

pool.on("error", (error) => {
  console.error(
    "❌ PostgreSQL pool error:",
    error
  );
});

/* =====================================================
   MIDDLEWARE
===================================================== */

app.disable("x-powered-by");

app.set("trust proxy", 1);

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

/* =====================================================
   HELPERS
===================================================== */

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

function cleanUsername(username) {
  return String(
    username ?? ""
  ).trim();
}

function normalizeUsername(username) {
  return cleanUsername(
    username
  ).toLowerCase();
}

function validUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,24}$/.test(
    username
  );
}

function validPassword(password) {
  if (
    typeof password !== "string"
  ) {
    return false;
  }

  const bytes =
    Buffer.byteLength(
      password,
      "utf8"
    );

  return (
    bytes >= 6 &&
    bytes <= 72
  );
}

function validAccessKey(key) {
  return (
    typeof key === "string" &&
    /^N10-[A-Za-z0-9]+$/.test(
      key
    )
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

function generateSessionToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

/* =====================================================
   FRONTEND REDIRECT
===================================================== */

function frontendRedirect(
  params = {}
) {
  const url =
    new URL(
      FRONTEND_URL + "/"
    );

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

/* =====================================================
   OAUTH STATE
===================================================== */

function createOAuthState() {
  if (!OAUTH_STATE_SECRET) {
    throw new Error(
      "OAUTH_STATE_SECRET missing"
    );
  }

  const timestamp =
    Date.now().toString();

  const random =
    crypto
      .randomBytes(32)
      .toString("hex");

  const payload =
    `${timestamp}.${random}`;

  const signature =
    crypto
      .createHmac(
        "sha256",
        OAUTH_STATE_SECRET
      )
      .update(payload)
      .digest("hex");

  return (
    `${payload}.${signature}`
  );
}

function verifyOAuthState(state) {
  if (
    typeof state !== "string" ||
    !state
  ) {
    return false;
  }

  const parts =
    state.split(".");

  if (
    parts.length !== 3
  ) {
    return false;
  }

  const [
    timestamp,
    random,
    signature
  ] = parts;

  if (
    !timestamp ||
    !random ||
    !/^[a-f0-9]{64}$/.test(
      signature
    )
  ) {
    return false;
  }

  const payload =
    `${timestamp}.${random}`;

  const expected =
    crypto
      .createHmac(
        "sha256",
        OAUTH_STATE_SECRET
      )
      .update(payload)
      .digest("hex");

  const a =
    Buffer.from(
      signature,
      "hex"
    );

  const b =
    Buffer.from(
      expected,
      "hex"
    );

  if (
    a.length !== b.length
  ) {
    return false;
  }

  if (
    !crypto.timingSafeEqual(
      a,
      b
    )
  ) {
    return false;
  }

  const createdAt =
    Number(timestamp);

  if (
    !Number.isFinite(
      createdAt
    )
  ) {
    return false;
  }

  const age =
    Date.now() -
    createdAt;

  return (
    age >= 0 &&
    age <=
      10 * 60 * 1000
  );
}

/* =====================================================
   DATABASE INIT
===================================================== */

async function initDatabase() {
  if (!DATABASE_URL) {
    throw new Error(
      "DATABASE_URL غير موجود"
    );
  }

  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    /* USERS */

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,

        username VARCHAR(24)
          NOT NULL,

        username_normalized VARCHAR(24)
          UNIQUE NOT NULL,

        password_hash TEXT
          NOT NULL,

        access_key TEXT
          UNIQUE NOT NULL,

        discord_id TEXT
          UNIQUE,

        created_at TIMESTAMP
          DEFAULT CURRENT_TIMESTAMP
      )
    `);

    /* ACCESS KEYS */

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

    /* SESSIONS */

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

    /* MIGRATION */

    await client.query(`
      ALTER TABLE sessions
      ADD COLUMN IF NOT EXISTS
      expires_at TIMESTAMP
    `);

    await client.query(`
      UPDATE sessions
      SET expires_at =
        created_at +
        INTERVAL '30 days'
      WHERE expires_at IS NULL
    `);

    /* INDEXES */

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_access_keys_discord_id
      ON access_keys(discord_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_sessions_user_id
      ON sessions(user_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_sessions_expires_at
      ON sessions(expires_at)
    `);

    await client.query(
      "COMMIT"
    );

    console.log(
      "✅ PostgreSQL database جاهزة"
    );
  } catch (error) {
    await client.query(
      "ROLLBACK"
    );

    console.error(
      "❌ Database initialization error:",
      error
    );

    throw error;
  } finally {
    client.release();
  }
}

/* =====================================================
   HOME
===================================================== */

app.get(
  "/",
  (req, res) => {
    res.json({
      success: true,
      name: "N10 SERVER MENA",
      status: "online"
    });
  }
);

/* =====================================================
   HEALTH
===================================================== */

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

/* =====================================================
   DISCORD LOGIN
===================================================== */

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

      const state =
        createOAuthState();

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

          state
        });

      return res.redirect(
        "https://discord.com/oauth2/authorize?" +
        params.toString()
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

/* =====================================================
   DISCORD CALLBACK
===================================================== */

app.get(
  "/auth/discord/callback",
  async (req, res) => {
    try {
      const code =
        String(
          req.query.code ?? ""
        );

      const state =
        String(
          req.query.state ?? ""
        );

      /* STATE */

      if (
        !verifyOAuthState(
          state
        )
      ) {
        return res.redirect(
          frontendRedirect({
            error:
              "invalid_oauth_state"
          })
        );
      }

      /* DISCORD CANCELLED */

      if (!code) {
        return res.redirect(
          frontendRedirect({
            error:
              "discord_cancelled"
          })
        );
      }

      /* TOKEN */

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

      /* DISCORD USER */

      const userResponse =
        await fetch(
          "https://discord.com/api/v10/users/@me",
          {
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

      /* =================================================
         EXISTING USER
      ================================================= */

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

        /*
          Existing account:
          return access key + existing.
        */

        return res.redirect(
          frontendRedirect({
            accessKey:
              user.access_key,

            discord:
              "existing"
          })
        );
      }

      /* =================================================
         EXISTING UNUSED KEY
      ================================================= */

      const existingKey =
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

      let accessKey =
        existingKey.rows.length > 0
          ? existingKey.rows[0]
              .access_key
          : null;

      /* =================================================
         CREATE NEW ACCESS KEY
      ================================================= */

      if (!accessKey) {
        for (
          let attempt = 0;
          attempt < 10;
          attempt++
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

            break;
          } catch (error) {
            if (
              error.code ===
              "23505"
            ) {
              continue;
            }

            throw error;
          }
        }
      }

      if (!accessKey) {
        console.error(
          "❌ Could not generate Access Key"
        );

        return res.redirect(
          frontendRedirect({
            error:
              "key_generation_failed"
          })
        );
      }

      console.log(
        "✅ Access Key generated"
      );

      /* =================================================
         SEND KEY TO FRONTEND
      ================================================= */

      return res.redirect(
        frontendRedirect({
          accessKey,
          discord:
            "new"
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

/* =====================================================
   REGISTER
===================================================== */

app.post(
  "/api/register",
  async (req, res) => {
    const {
      username,
      password,
      confirmPassword,
      accessKey
    } = req.body || {};

    const cleanName =
      cleanUsername(
        username
      );

    const normalizedName =
      normalizeUsername(
        username
      );

    const key =
      String(
        accessKey ?? ""
      ).trim();

    /* REQUIRED */

    if (
      !cleanName ||
      typeof password !== "string" ||
      typeof confirmPassword !== "string" ||
      !key
    ) {
      return sendError(
        res,
        400,
        "الرجاء ملء جميع الخانات."
      );
    }

    /* USERNAME */

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

    /* PASSWORD */

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

    /* CONFIRM */

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

    /* ACCESS KEY */

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

      /* LOCK KEY */

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

      if (
        keyRow.used
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

      /* USERNAME CHECK */

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

      /* PASSWORD */

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      /* CREATE USER */

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

      /* MARK KEY USED */

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
      await client.query(
        "ROLLBACK"
      );

      console.error(
        "❌ Register error:",
        error
      );

      if (
        error.code ===
        "23505"
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

/* =====================================================
   LOGIN
===================================================== */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const {
        username,
        password
      } = req.body || {};

      const normalizedName =
        normalizeUsername(
          username
        );

      if (
        !normalizedName ||
        typeof password !== "string"
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

      /* SESSION */

      const token =
        generateSessionToken();

      const expiresAt =
        new Date(
          Date.now() +
          SESSION_MS
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
          id:
            user.id,

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

/* =====================================================
   AUTH USER
===================================================== */

async function getAuthenticatedUser(
  req
) {
  const auth =
    req.headers.authorization ||
    "";

  if (
    !auth.startsWith(
      "Bearer "
    )
  ) {
    return null;
  }

  const token =
    auth
      .substring(7)
      .trim();

  if (!token) {
    return null;
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
      WHERE s.token = $1
        AND s.expires_at > CURRENT_TIMESTAMP
      LIMIT 1
      `,
      [token]
    );

  if (
    result.rows.length === 0
  ) {
    await pool.query(
      `
      DELETE FROM sessions
      WHERE token = $1
      `,
      [token]
    );

    return null;
  }

  return result.rows[0];
}

/* =====================================================
   GET USER
===================================================== */

app.get(
  "/api/user",
  async (req, res) => {
    try {
      const user =
        await getAuthenticatedUser(
          req
        );

      if (!user) {
        return sendError(
          res,
          401,
          "Session منتهية أو غير صالحة."
        );
      }

      return res.json({
        success: true,

        user: {
          id:
            user.id,

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
        "❌ User error:",
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

/* =====================================================
   LOGOUT
===================================================== */

app.post(
  "/api/logout",
  async (req, res) => {
    try {
      const auth =
        req.headers.authorization ||
        "";

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

/* =====================================================
   CLEANUP SESSIONS
===================================================== */

async function cleanupSessions() {
  try {
    await pool.query(
      `
      DELETE FROM sessions
      WHERE expires_at <= CURRENT_TIMESTAMP
      `
    );
  } catch (error) {
    console.error(
      "❌ Session cleanup error:",
      error
    );
  }
}

/* =====================================================
   404
===================================================== */

app.use(
  (req, res) => {
    return res.status(404).json({
      success: false,

      message:
        "المسار غير موجود.",

      path:
        req.path
    });
  }
);

/* =====================================================
   ERROR HANDLER
===================================================== */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "❌ Unhandled server error:",
      error
    );

    return res.status(500).json({
      success: false,

      message:
        "حدث خطأ داخلي في السيرفر."
    });
  }
);

/* =====================================================
   START SERVER
===================================================== */

async function startServer() {
  try {
    await initDatabase();

    const server =
      app.listen(
        PORT,
        "0.0.0.0",
        () => {
          console.log(
            "===================================="
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
            "===================================="
          );
        }
      );

    server.on(
      "error",
      (error) => {
        console.error(
          "❌ Server error:",
          error
        );

        process.exit(1);
      }
    );

    setInterval(
      cleanupSessions,
      60 * 60 * 1000
    ).unref();
  } catch (error) {
    console.error(
      "❌ Server startup failed:",
      error
    );

    process.exit(1);
  }
}

/* =====================================================
   SHUTDOWN
===================================================== */

async function shutdown(
  signal
) {
  console.log(
    `🛑 ${signal} received`
  );

  try {
    await pool.end();

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
  () => shutdown("SIGTERM")
);

process.on(
  "SIGINT",
  () => shutdown("SIGINT")
);

/* =====================================================
   START
===================================================== */

startServer();
