"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

/* =====================================================
   SETTINGS
===================================================== */

const PORT = Number(process.env.PORT || 3000);

const FRONTEND_URL = (
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io"
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

/* =====================================================
   CHECK ENV
===================================================== */

if (!DATABASE_URL) {
  console.error("❌ DATABASE_URL missing");
}

if (!DISCORD_CLIENT_ID) {
  console.error("❌ DISCORD_CLIENT_ID missing");
}

if (!DISCORD_CLIENT_SECRET) {
  console.error("❌ DISCORD_CLIENT_SECRET missing");
}

if (!OAUTH_STATE_SECRET) {
  console.error("❌ OAUTH_STATE_SECRET missing");
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
    ]
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

function errorResponse(
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
  return String(username ?? "").trim();
}

function normalizeUsername(username) {
  return cleanUsername(username)
    .toLowerCase();
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

  const size =
    Buffer.byteLength(
      password,
      "utf8"
    );

  return (
    size >= 6 &&
    size <= 72
  );
}

function validAccessKey(key) {
  return (
    typeof key === "string" &&
    /^N10-[A-Za-z0-9]+$/.test(key)
  );
}

/* =====================================================
   ACCESS KEY
===================================================== */

function generateAccessKey() {
  return (
    "N10-" +
    crypto
      .randomBytes(18)
      .toString("hex")
  );
}

/* =====================================================
   SESSION
===================================================== */

function generateSessionToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

/* =====================================================
   OAUTH STATE
===================================================== */

function createOAuthState() {
  const timestamp =
    Date.now().toString();

  const random =
    crypto
      .randomBytes(32)
      .toString("hex");

  const data =
    `${timestamp}.${random}`;

  const signature =
    crypto
      .createHmac(
        "sha256",
        OAUTH_STATE_SECRET
      )
      .update(data)
      .digest("hex");

  return (
    `${data}.${signature}`
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

  if (parts.length !== 3) {
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
    !signature
  ) {
    return false;
  }

  if (
    !/^[a-f0-9]{64}$/.test(
      signature
    )
  ) {
    return false;
  }

  const data =
    `${timestamp}.${random}`;

  const expected =
    crypto
      .createHmac(
        "sha256",
        OAUTH_STATE_SECRET
      )
      .update(data)
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

  const created =
    Number(timestamp);

  if (
    !Number.isFinite(created)
  ) {
    return false;
  }

  const age =
    Date.now() - created;

  return (
    age >= 0 &&
    age <=
      10 * 60 * 1000
  );
}

/* =====================================================
   FRONTEND REDIRECT
===================================================== */

function redirectToFrontend(
  params = {}
) {
  const url =
    new URL(
      FRONTEND_URL
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
   DATABASE INIT
===================================================== */

async function initDatabase() {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    /*
    USERS
    */

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

    /*
    ACCESS KEYS
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
    SESSIONS
    */

    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,

        token TEXT
          UNIQUE NOT NULL,

        user_id INTEGER
          NOT NULL,

        created_at TIMESTAMP
          DEFAULT CURRENT_TIMESTAMP
      )
    `);

    /*
    إضافة expires_at إذا الجدول قديم
    */

    await client.query(`
      ALTER TABLE sessions
      ADD COLUMN IF NOT EXISTS
      expires_at TIMESTAMP
    `);

    /*
    الجلسات القديمة
    */

    await client.query(`
      UPDATE sessions
      SET expires_at =
        created_at +
        INTERVAL '30 days'
      WHERE expires_at IS NULL
    `);

    /*
    INDEXES
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
      idx_sessions_expiry
      ON sessions(expires_at)
    `);

    await client.query(
      "COMMIT"
    );

    console.log(
      "✅ Database ready"
    );
  } catch (error) {
    await client.query(
      "ROLLBACK"
    );

    console.error(
      "❌ Database error:",
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

      res.json({
        success: true,
        status: "online",
        database: "connected"
      });
    } catch (error) {
      console.error(
        "Health error:",
        error
      );

      res.status(500).json({
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
        return errorResponse(
          res,
          500,
          "Discord environment variables ناقصة."
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

      const url =
        "https://discord.com/oauth2/authorize?" +
        params.toString();

      return res.redirect(
        url
      );
    } catch (error) {
      console.error(
        "Discord start error:",
        error
      );

      return errorResponse(
        res,
        500,
        "تعذر تشغيل Discord Login."
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
          req.query.code || ""
        );

      const state =
        String(
          req.query.state || ""
        );

      /*
      تحقق State
      */

      if (
        !verifyOAuthState(
          state
        )
      ) {
        console.error(
          "❌ OAuth state invalid"
        );

        return res.redirect(
          redirectToFrontend({
            error:
              "invalid_oauth_state"
          })
        );
      }

      /*
      Discord cancel
      */

      if (!code) {
        return res.redirect(
          redirectToFrontend({
            error:
              "discord_cancelled"
          })
        );
      }

      /*
      TOKEN
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
          "Discord token error:",
          tokenData
        );

        return res.redirect(
          redirectToFrontend({
            error:
              "discord_token_error"
          })
        );
      }

      /*
      USER
      */

      const discordResponse =
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
        await discordResponse.json();

      if (
        !discordResponse.ok ||
        !discordUser.id
      ) {
        console.error(
          "Discord user error:",
          discordUser
        );

        return res.redirect(
          redirectToFrontend({
            error:
              "discord_user_error"
          })
        );
      }

      const discordId =
        String(
          discordUser.id
        );

      /*
      هل عنده حساب N10؟
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
        existingUser.rows.length
      ) {
        const user =
          existingUser.rows[0];

        /*
        مهم:
        نرجع accessKey للواجهة
        */

        return res.redirect(
          redirectToFrontend({
            accessKey:
              user.access_key,

            discord:
              "existing"
          })
        );
      }

      /*
      هل عنده مفتاح سابق؟
      */

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

      let accessKey =
        oldKey.rows.length
          ? oldKey.rows[0].access_key
          : null;

      /*
      إنشاء مفتاح جديد
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
        return res.redirect(
          redirectToFrontend({
            error:
              "key_generation_failed"
          })
        );
      }

      /*
      أهم سطر:
      نرسل المفتاح للـ Frontend
      */

      return res.redirect(
        redirectToFrontend({
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
        redirectToFrontend({
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

    const name =
      cleanUsername(
        username
      );

    const normalized =
      normalizeUsername(
        username
      );

    const key =
      String(
        accessKey || ""
      ).trim();

    if (
      !name ||
      !password ||
      !confirmPassword ||
      !key
    ) {
      return errorResponse(
        res,
        400,
        "الرجاء ملء جميع الخانات."
      );
    }

    if (
      !validUsername(name)
    ) {
      return errorResponse(
        res,
        400,
        "اسم المستخدم غير صالح."
      );
    }

    if (
      !validPassword(password)
    ) {
      return errorResponse(
        res,
        400,
        "كلمة المرور يجب أن تكون بين 6 و72 بايت."
      );
    }

    if (
      password !==
      confirmPassword
    ) {
      return errorResponse(
        res,
        400,
        "كلمتا المرور غير متطابقتين."
      );
    }

    if (
      !validAccessKey(key)
    ) {
      return errorResponse(
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
      قفل المفتاح
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
        !keyResult.rows.length
      ) {
        await client.query(
          "ROLLBACK"
        );

        return errorResponse(
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

        return errorResponse(
          res,
          400,
          "Access Key مستعمل من قبل."
        );
      }

      /*
      تحقق username
      */

      const usernameExists =
        await client.query(
          `
          SELECT id
          FROM users
          WHERE username_normalized = $1
          LIMIT 1
          `,
          [normalized]
        );

      if (
        usernameExists.rows.length
      ) {
        await client.query(
          "ROLLBACK"
        );

        return errorResponse(
          res,
          409,
          "اسم المستخدم مستعمل من قبل."
        );
      }

      /*
      password hash
      */

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      /*
      إنشاء المستخدم
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
            name,
            normalized,
            passwordHash,
            keyRow.access_key,
            keyRow.discord_id
          ]
        );

      const user =
        userResult.rows[0];

      /*
      الآن فقط:
      المفتاح يصبح USED
      */

      await client.query(
        `
        UPDATE access_keys
        SET
          used = TRUE,
          used_by = $1,
          used_at =
            CURRENT_TIMESTAMP
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

      return res.status(201).json({
        success: true,

        message:
          "تم إنشاء الحساب بنجاح.",

        user: {
          id:
            user.id,

          username:
            user.username,

          accessKey:
            user.access_key,

          discordId:
            user.discord_id
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
        return errorResponse(
          res,
          409,
          "اسم المستخدم أو Access Key مستعمل من قبل."
        );
      }

      return errorResponse(
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

      const normalized =
        normalizeUsername(
          username
        );

      if (
        !normalized ||
        typeof password !==
          "string"
      ) {
        return errorResponse(
          res,
          400,
          "أدخل اسم المستخدم وكلمة المرور."
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
          [normalized]
        );

      if (
        !result.rows.length
      ) {
        return errorResponse(
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
        return errorResponse(
          res,
          401,
          "اسم المستخدم أو كلمة المرور غير صحيحة."
        );
      }

      /*
      Session
      */

      const token =
        generateSessionToken();

      const expires =
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
          expires
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

      return errorResponse(
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

async function getUserFromToken(
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
      INNER JOIN users u
        ON u.id = s.user_id
      WHERE s.token = $1
        AND s.expires_at >
            CURRENT_TIMESTAMP
      LIMIT 1
      `,
      [token]
    );

  if (
    !result.rows.length
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
        await getUserFromToken(
          req
        );

      if (!user) {
        return errorResponse(
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
        "User error:",
        error
      );

      return errorResponse(
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
        "Logout error:",
        error
      );

      return errorResponse(
        res,
        500,
        "حدث خطأ أثناء تسجيل الخروج."
      );
    }
  }
);

/* =====================================================
   404
===================================================== */

app.use(
  (req, res) => {
    res.status(404).json({
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
      "❌ Server error:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "حدث خطأ داخلي في السيرفر."
    });
  }
);

/* =====================================================
   START
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
            `🌐 PORT: ${PORT}`
          );

          console.log(
            `🔗 FRONTEND: ${FRONTEND_URL}`
          );

          console.log(
            `🔗 DISCORD CALLBACK: ${DISCORD_REDIRECT_URI}`
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
          "❌ Listen error:",
          error
        );

        process.exit(1);
      }
    );

    /*
    تنظيف Sessions القديمة
    كل ساعة
    */

    setInterval(
      async () => {
        try {
          await pool.query(
            `
            DELETE FROM sessions
            WHERE expires_at <=
                  CURRENT_TIMESTAMP
            `
          );
        } catch (error) {
          console.error(
            "Session cleanup error:",
            error
          );
        }
      },
      60 * 60 * 1000
    ).unref();
  } catch (error) {
    console.error(
      "❌ Startup failed:",
      error
    );

    process.exit(1);
  }
}

/* =====================================================
   SHUTDOWN
===================================================== */

process.on(
  "SIGTERM",
  async () => {
    await pool.end();
    process.exit(0);
  }
);

process.on(
  "SIGINT",
  async () => {
    await pool.end();
    process.exit(0);
  }
);

startServer();
