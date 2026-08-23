"use strict";

/*
========================================================
 N10 SERVER MENA
 Backend كامل ومصحح
========================================================

- Discord OAuth2
- OAuth State protection
- Access Keys
- Register
- Login
- PostgreSQL
- Sessions
- Password hashing
- CORS مضبوط
- Health Check
- Logout
- Session expiration
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

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io";

const DISCORD_CLIENT_ID =
  process.env.DISCORD_CLIENT_ID;

const DISCORD_CLIENT_SECRET =
  process.env.DISCORD_CLIENT_SECRET;

const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI ||
  "https://n10-discord-backend-new.onrender.com/auth/discord/callback";

const DATABASE_URL =
  process.env.DATABASE_URL;

/*
========================================================
 OAuth State Secret
========================================================
*/

const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET ||
  DISCORD_CLIENT_SECRET;

/*
========================================================
 Session مدة الصلاحية
 30 يوم
========================================================
*/

const SESSION_DAYS = 30;

const SESSION_MS =
  SESSION_DAYS *
  24 *
  60 *
  60 *
  1000;

/*
========================================================
 التحقق من Environment Variables
========================================================
*/

if (!DATABASE_URL) {
  console.error(
    "❌ DATABASE_URL غير موجود."
  );
}

if (!DISCORD_CLIENT_ID) {
  console.error(
    "❌ DISCORD_CLIENT_ID غير موجود."
  );
}

if (!DISCORD_CLIENT_SECRET) {
  console.error(
    "❌ DISCORD_CLIENT_SECRET غير موجود."
  );
}

if (!OAUTH_STATE_SECRET) {
  console.error(
    "❌ OAUTH_STATE_SECRET غير موجود."
  );
}

/*
========================================================
 PostgreSQL
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
 Middleware
========================================================
*/

app.disable("x-powered-by");

/*
--------------------------------------------------------
 CORS
--------------------------------------------------------
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
--------------------------------------------------------
 JSON
--------------------------------------------------------
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
 Helpers
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
--------------------------------------------------------
 Username
--------------------------------------------------------
*/

function cleanUsername(username) {
  return String(username || "").trim();
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

/*
--------------------------------------------------------
 Password
--------------------------------------------------------
*/

function validPassword(password) {
  if (
    typeof password !== "string"
  ) {
    return false;
  }

  const length =
    Buffer.byteLength(
      password,
      "utf8"
    );

  return (
    length >= 6 &&
    length <= 72
  );
}

/*
--------------------------------------------------------
 Access Key
--------------------------------------------------------
*/

function validAccessKey(key) {
  return (
    typeof key === "string" &&
    /^N10-[A-Za-z0-9]+$/.test(
      key
    )
  );
}

/*
========================================================
 Generate Access Key
========================================================
*/

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
 Generate Session Token
========================================================
*/

function generateSessionToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

/*
========================================================
 OAuth State
========================================================

نستعمل HMAC باش نمنعو OAuth CSRF.
========================================================
*/

function createOAuthState() {
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

  return `${payload}.${signature}`;
}

/*
========================================================
 Verify OAuth State
========================================================
*/

function verifyOAuthState(state) {
  if (
    !state ||
    typeof state !== "string"
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

  if (
    signature.length !==
    expected.length
  ) {
    return false;
  }

  const validSignature =
    crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );

  if (!validSignature) {
    return false;
  }

  const createdAt =
    Number(timestamp);

  if (
    !Number.isFinite(createdAt)
  ) {
    return false;
  }

  /*
  State صالح لمدة 10 دقائق فقط
  */

  const age =
    Date.now() - createdAt;

  if (
    age < 0 ||
    age > 10 * 60 * 1000
  ) {
    return false;
  }

  return true;
}

/*
========================================================
 Frontend URL
========================================================
*/

function frontendRedirect(
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

/*
========================================================
 Database
========================================================
*/

async function initDatabase() {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    /*
    ====================================================
    USERS
    ====================================================
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
          NOT NULL
      )
    `);

    /*
    ====================================================
    Migration بسيطة
    إذا sessions كانت موجودة من النسخة القديمة
    ====================================================
    */

    await client.query(`
      ALTER TABLE sessions
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP
    `);

    /*
    إذا كانت sessions القديمة فيها expires_at NULL
    نعطيها مدة 30 يوم.
    */

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
    Indexes
    ====================================================
    */

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
      "✅ PostgreSQL database جاهزة."
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

/*
========================================================
 HOME
========================================================
*/

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

/*
========================================================
 DISCORD LOGIN
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
          "إعدادات Discord ناقصة في السيرفر."
        );
      }

      /*
      إنشاء State
      */

      const state =
        createOAuthState();

      /*
      Discord OAuth
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

          state
        });

      const discordURL =
        "https://discord.com/oauth2/authorize?" +
        params.toString();

      return res.redirect(
        discordURL
      );
    } catch (error) {
      console.error(
        "Discord auth error:",
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

      const state =
        String(
          req.query.state || ""
        );

      /*
      --------------------------------------------------
      التحقق من State
      --------------------------------------------------
      */

      if (
        !verifyOAuthState(
          state
        )
      ) {
        console.error(
          "❌ Invalid OAuth state."
        );

        return res.redirect(
          frontendRedirect({
            error:
              "invalid_oauth_state"
          })
        );
      }

      /*
      --------------------------------------------------
      المستخدم ألغى Discord
      --------------------------------------------------
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
      OAuth TOKEN
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

      /*
      ==================================================
      إذا Discord عنده حساب N10 مسبقاً
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

        return res.redirect(
          frontendRedirect({
            accessKey:
              user.access_key
          })
        );
      }

      /*
      ==================================================
      مهم:
      إذا Discord هذا عنده Access Key غير مستعمل
      نستعمل نفس المفتاح بدل إنشاء مفاتيح كثيرة.
      ==================================================
      */

      let accessKey = null;

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

      if (
        existingKey.rows.length > 0
      ) {
        accessKey =
          existingKey.rows[0]
            .access_key;
      }

      /*
      ==================================================
      إذا ما عندوش مفتاح:
      إنشاء واحد جديد
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

            break;
          } catch (error) {
            /*
            إذا كان المفتاح مكرر
            نعاود المحاولة.
            */

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
          frontendRedirect({
            error:
              "key_generation_failed"
          })
        );
      }

      /*
      ==================================================
      إرسال المستخدم للـ Frontend
      ==================================================
      */

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
      cleanUsername(
        username
      );

    const normalizedName =
      normalizeUsername(
        username
      );

    const key =
      String(
        accessKey || ""
      ).trim();

    /*
    --------------------------------------------------
    Required
    --------------------------------------------------
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

    /*
    --------------------------------------------------
    Username
    --------------------------------------------------
    */

    if (
      !validUsername(
        cleanName
      )
    ) {
      return sendError(
        res,
        400,
        "اسم المستخدم يجب أن يحتوي على 3 إلى 24 حرفاً، ويمكن استعمال الأرقام و _ و - و ."
      );
    }

    /*
    --------------------------------------------------
    Password
    --------------------------------------------------
    */

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

    /*
    --------------------------------------------------
    Confirm Password
    --------------------------------------------------
    */

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

    /*
    --------------------------------------------------
    Access Key
    --------------------------------------------------
    */

    if (
      !validAccessKey(
        key
      )
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
      USERNAME CHECK
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
      ACCESS KEY CHECK + LOCK
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
          "Access Key غير صالح أو غير موجود."
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
          "Access Key غير صالح أو مستعمل."
        );
      }

      /*
      ==================================================
      Discord ID لازم يكون موجود
      ==================================================
      */

      if (
        !keyRow.discord_id
      ) {
        await client.query(
          "ROLLBACK"
        );

        return sendError(
          res,
          400,
          "Access Key غير مربوط بحساب Discord."
        );
      }

      /*
      ==================================================
      تحقق إضافي:
      Discord ما يكونش مربوط بحساب آخر
      ==================================================
      */

      const discordExists =
        await client.query(
          `
          SELECT id
          FROM users
          WHERE discord_id = $1
          LIMIT 1
          `,
          [keyRow.discord_id]
        );

      if (
        discordExists.rows.length > 0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return sendError(
          res,
          409,
          "حساب Discord هذا عنده حساب N10 من قبل."
        );
      }

      /*
      ==================================================
      HASH PASSWORD
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
      KEY يصبح USED هنا فقط
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

      /*
      ==================================================
      SUCCESS
      ==================================================
      */

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
            user.access_key
        }
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

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
          "اسم المستخدم أو Access Key أو Discord مستعمل من قبل."
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

      /*
      ==================================================
      FIND USER
      ==================================================
      */

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

      /*
      ==================================================
      PASSWORD
      ==================================================
      */

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
      حذف sessions القديمة للمستخدم
      ==================================================
      */

      await pool.query(
        `
        DELETE FROM sessions
        WHERE user_id = $1
        `,
        [user.id]
      );

      /*
      ==================================================
      CREATE SESSION
      ==================================================
      */

      const sessionToken =
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
          sessionToken,
          user.id,
          expiresAt
        ]
      );

      /*
      ==================================================
      SUCCESS
      ==================================================
      */

      return res.json({
        success: true,

        message:
          "تم تسجيل الدخول بنجاح.",

        token:
          sessionToken,

        accessKey:
          user.access_key,

        expiresAt,

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
        req.headers.authorization ||
        "";

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

      /*
      ==================================================
      حذف sessions منتهية
      ==================================================
      */

      await pool.query(
        `
        DELETE FROM sessions
        WHERE expires_at <= CURRENT_TIMESTAMP
        `
      );

      /*
      ==================================================
      GET USER
      ==================================================
      */

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

/*
========================================================
 CLEAN EXPIRED SESSIONS
========================================================

كل ساعة ننظف sessions القديمة.
========================================================
*/

setInterval(
  async () => {
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
  },
  60 * 60 * 1000
);

/*
========================================================
 404
========================================================
*/

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

/*
========================================================
 GLOBAL ERROR
========================================================
*/

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "❌ Unhandled error:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

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
    /*
    ----------------------------------------------------
    تحقق نهائي
    ----------------------------------------------------
    */

    if (!DATABASE_URL) {
      throw new Error(
        "DATABASE_URL غير موجود"
      );
    }

    if (!DISCORD_CLIENT_ID) {
      throw new Error(
        "DISCORD_CLIENT_ID غير موجود"
      );
    }

    if (!DISCORD_CLIENT_SECRET) {
      throw new Error(
        "DISCORD_CLIENT_SECRET غير موجود"
      );
    }

    if (!OAUTH_STATE_SECRET) {
      throw new Error(
        "OAUTH_STATE_SECRET غير موجود"
      );
    }

    /*
    ----------------------------------------------------
    Database
    ----------------------------------------------------
    */

    await initDatabase();

    /*
    ----------------------------------------------------
    Server
    ----------------------------------------------------
    */

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
          `🔗 Frontend: ${FRONTEND_URL}`
        );

        console.log(
          `🔗 Discord Callback: ${DISCORD_REDIRECT_URI}`
        );

        console.log(
          "🔐 OAuth State: ENABLED"
        );

        console.log(
          "🔐 Sessions: ENABLED"
        );

        console.log(
          `⏱️ Session: ${SESSION_DAYS} days`
        );

        console.log(
          "===================================="
        );
      }
    );
  } catch (error) {
    console.error(
      "❌ Server startup failed:",
      error
    );

    process.exit(1);
  }
}

startServer();
