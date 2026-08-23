"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 10000);

const FRONTEND_URL = String(
  process.env.FRONTEND_URL ||
    "https://siko6476.github.io/N10-SERVER-MENA"
).replace(/\/+$/, "");

const FRONTEND_ORIGIN = String(
  process.env.FRONTEND_ORIGIN ||
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
  process.env.OAUTH_STATE_SECRET || "";

const ADMIN_KEY =
  process.env.ADMIN_KEY || "";

const SESSION_DAYS = 30;

const SESSION_MS =
  SESSION_DAYS *
  24 *
  60 *
  60 *
  1000;


/* =========================================================
   ENVIRONMENT CHECK
========================================================= */

const missing = [];

if (!DATABASE_URL) {
  missing.push("DATABASE_URL");
}

if (!DISCORD_CLIENT_ID) {
  missing.push("DISCORD_CLIENT_ID");
}

if (!DISCORD_CLIENT_SECRET) {
  missing.push("DISCORD_CLIENT_SECRET");
}

if (!DISCORD_REDIRECT_URI) {
  missing.push("DISCORD_REDIRECT_URI");
}

if (!FRONTEND_URL) {
  missing.push("FRONTEND_URL");
}

if (!FRONTEND_ORIGIN) {
  missing.push("FRONTEND_ORIGIN");
}

if (!OAUTH_STATE_SECRET) {
  missing.push("OAUTH_STATE_SECRET");
}

if (missing.length > 0) {
  console.error(
    "❌ Missing Environment Variables:",
    missing.join(", ")
  );
}


/* =========================================================
   POSTGRESQL
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL || undefined,

  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
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


/* =========================================================
   MIDDLEWARE
========================================================= */

app.disable("x-powered-by");

app.set("trust proxy", 1);


/* =========================================================
   CORS
========================================================= */

const allowedOrigins = [
  FRONTEND_ORIGIN
];

app.use(
  cors({
    origin: function (origin, callback) {

      /*
        Requests without Origin:
        مثل health checks وبعض أدوات السيرفر.
      */

      if (!origin) {
        return callback(null, true);
      }

      if (
        allowedOrigins.includes(origin)
      ) {
        return callback(null, true);
      }

      console.error(
        "❌ CORS blocked origin:",
        origin
      );

      return callback(
        new Error("Not allowed by CORS")
      );
    },

    methods: [
      "GET",
      "POST",
      "OPTIONS"
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Admin-Key"
    ],

    credentials: false,

    optionsSuccessStatus: 204
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


/* =========================================================
   HELPERS
========================================================= */

function sendError(
  res,
  status,
  message
) {
  return res
    .status(status)
    .json({
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


function validAccessKey(key) {

  return (
    typeof key === "string" &&
    /^N10-[A-Za-z0-9]+$/.test(key)
  );
}


/* =========================================================
   TOKENS
========================================================= */

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


/* =========================================================
   NO CACHE
========================================================= */

function noCache(res) {

  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );

  res.setHeader(
    "Pragma",
    "no-cache"
  );

  res.setHeader(
    "Expires",
    "0"
  );
}


/* =========================================================
   FRONTEND REDIRECT
========================================================= */

function frontendRedirect(params = {}) {

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


/* =========================================================
   OAUTH STATE
========================================================= */

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
    Date.now() - createdAt;

  return (
    age >= 0 &&
    age <= 10 * 60 * 1000
  );
}


/* =========================================================
   CREATE ACCESS KEY
========================================================= */

async function createAccessKey(
  discordId
) {

  for (
    let attempt = 0;
    attempt < 50;
    attempt++
  ) {

    const newKey =
      generateAccessKey();

    try {

      const result =
        await pool.query(
          `
          INSERT INTO access_keys
          (
            key,
            used,
            used_by,
            account_id,
            discord_id,
            created_at,
            used_at
          )
          VALUES
          (
            $1,
            FALSE,
            NULL,
            NULL,
            $2,
            NOW(),
            NULL
          )
          RETURNING
            id,
            key,
            used,
            used_by,
            account_id,
            discord_id,
            created_at,
            used_at
          `,
          [
            newKey,
            discordId
          ]
        );

      return result.rows[0];

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

  throw new Error(
    "Unable to generate unique Access Key"
  );
}


/* =========================================================
   INVALIDATE OLD DISCORD KEYS
========================================================= */

async function invalidateOldDiscordKeys(
  discordId,
  accountId,
  username
) {

  if (!discordId) {
    return;
  }

  await pool.query(
    `
    UPDATE access_keys
    SET
      used = TRUE,
      used_by = COALESCE(
        used_by,
        $2
      ),
      account_id = COALESCE(
        account_id,
        $3
      ),
      used_at = COALESCE(
        used_at,
        NOW()
      )
    WHERE
      discord_id = $1
      AND used = FALSE
    `,
    [
      discordId,
      username || null,
      accountId || null
    ]
  );
}


/* =========================================================
   DATABASE INIT
========================================================= */

async function initDatabase() {

  const client =
    await pool.connect();

  try {

    await client.query(
      "BEGIN"
    );


    /* =====================================================
       ACCOUNTS
    ===================================================== */

    await client.query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,

        username VARCHAR(24)
          NOT NULL UNIQUE,

        password TEXT,

        access_key TEXT,

        discord_id TEXT,

        discord_username TEXT,

        discord_global_name TEXT,

        discord_avatar TEXT,

        discord_email TEXT,

        auth_provider VARCHAR(20)
          DEFAULT 'password',

        created_at TIMESTAMPTZ
          DEFAULT NOW(),

        last_login_at TIMESTAMPTZ
      )
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS password TEXT
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS access_key TEXT
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS discord_id TEXT
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS discord_username TEXT
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS discord_global_name TEXT
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS discord_avatar TEXT
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS discord_email TEXT
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(20)
      DEFAULT 'password'
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ
      DEFAULT NOW()
    `);


    await client.query(`
      ALTER TABLE accounts
      ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ
    `);


    /* =====================================================
       ACCESS KEYS
    ===================================================== */

    await client.query(`
      CREATE TABLE IF NOT EXISTS access_keys (
        id SERIAL PRIMARY KEY,

        key TEXT
          UNIQUE
          NOT NULL,

        used BOOLEAN
          NOT NULL
          DEFAULT FALSE,

        used_by TEXT,

        account_id INTEGER,

        discord_id TEXT,

        created_at TIMESTAMPTZ
          DEFAULT NOW(),

        used_at TIMESTAMPTZ
      )
    `);


    await client.query(`
      ALTER TABLE access_keys
      ADD COLUMN IF NOT EXISTS used BOOLEAN
      DEFAULT FALSE
    `);


    await client.query(`
      ALTER TABLE access_keys
      ADD COLUMN IF NOT EXISTS used_by TEXT
    `);


    await client.query(`
      ALTER TABLE access_keys
      ADD COLUMN IF NOT EXISTS account_id INTEGER
    `);


    await client.query(`
      ALTER TABLE access_keys
      ADD COLUMN IF NOT EXISTS discord_id TEXT
    `);


    await client.query(`
      ALTER TABLE access_keys
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ
      DEFAULT NOW()
    `);


    await client.query(`
      ALTER TABLE access_keys
      ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ
    `);


    /* =====================================================
       SESSIONS
    ===================================================== */

    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,

        token TEXT
          UNIQUE
          NOT NULL,

        user_id INTEGER
          NOT NULL,

        created_at TIMESTAMPTZ
          DEFAULT CURRENT_TIMESTAMP,

        expires_at TIMESTAMPTZ
          NOT NULL
      )
    `);


    await client.query(`
      ALTER TABLE sessions
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ
    `);


    await client.query(`
      UPDATE sessions
      SET expires_at =
        created_at +
        INTERVAL '30 days'
      WHERE expires_at IS NULL
    `);


    /* =====================================================
       INDEXES
    ===================================================== */

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_accounts_discord_id
      ON accounts(discord_id)
    `);


    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_accounts_username
      ON accounts(username)
    `);


    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_access_keys_discord_id
      ON access_keys(discord_id)
    `);


    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_access_keys_account_id
      ON access_keys(account_id)
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
      "✅ Database initialized"
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


/* =========================================================
   HOME
========================================================= */

app.get(
  "/",
  (req, res) => {

    noCache(res);

    res.json({
      success: true,
      name: "N10 SERVER MENA",
      status: "online",
      cors: FRONTEND_ORIGIN,
      frontend: FRONTEND_URL
    });
  }
);


/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/health",
  async (req, res) => {

    try {

      await pool.query(
        "SELECT 1"
      );

      noCache(res);

      res.json({
        success: true,
        status: "online",
        database: "connected",
        cors: FRONTEND_ORIGIN,
        frontend: FRONTEND_URL
      });

    } catch (error) {

      console.error(
        "❌ Health error:",
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


/* =========================================================
   DISCORD LOGIN
========================================================= */

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
            "identify email",

          state
        });


      noCache(res);

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


/* =========================================================
   DISCORD CALLBACK
========================================================= */

app.get(
  "/auth/discord/callback",
  async (req, res) => {

    try {

      noCache(res);


      const code =
        typeof req.query.code ===
        "string"
          ? req.query.code
          : "";


      const state =
        typeof req.query.state ===
        "string"
          ? req.query.state
          : "";


      const discordError =
        typeof req.query.error ===
        "string"
          ? req.query.error
          : "";


      if (discordError) {

        return res.redirect(
          frontendRedirect({
            discordError:
              "تم إلغاء تسجيل الدخول عبر Discord."
          })
        );
      }


      if (
        !verifyOAuthState(
          state
        )
      ) {

        return res.redirect(
          frontendRedirect({
            discordError:
              "رابط Discord غير صالح أو انتهت صلاحيته."
          })
        );
      }


      if (!code) {

        return res.redirect(
          frontendRedirect({
            discordError:
              "لم يتم استلام كود Discord."
          })
        );
      }


      /* ===================================================
         TOKEN
      =================================================== */

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
            discordError:
              "فشل الحصول على صلاحية Discord."
          })
        );
      }


      /* ===================================================
         USER
      =================================================== */

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
            discordError:
              "تعذر الحصول على بيانات Discord."
          })
        );
      }


      const discordId =
        String(
          discordUser.id
        );


      const discordUsername =
        String(
          discordUser.username || ""
        );


      const discordGlobalName =
        String(
          discordUser.global_name || ""
        );


      const discordEmail =
        String(
          discordUser.email || ""
        );


      const discordAvatar =
        discordUser.avatar
          ? `https://cdn.discordapp.com/avatars/${discordId}/${discordUser.avatar}.png`
          : "";


      console.log(
        "===================================="
      );

      console.log(
        "✅ Discord OAuth SUCCESS"
      );

      console.log(
        "Discord ID:",
        discordId
      );

      console.log(
        "Discord Username:",
        discordUsername
      );


      /* ===================================================
         FIND ACCOUNT
      =================================================== */

      const existingAccount =
        await pool.query(
          `
          SELECT
            id,
            username,
            access_key,
            discord_id
          FROM accounts
          WHERE discord_id = $1
          LIMIT 1
          `,
          [discordId]
        );


      /* ===================================================
         EXISTING ACCOUNT
      =================================================== */

      if (
        existingAccount.rows.length > 0
      ) {

        const account =
          existingAccount.rows[0];


        await invalidateOldDiscordKeys(
          discordId,
          account.id,
          account.username
        );


        const newKey =
          await createAccessKey(
            discordId
          );


        await pool.query(
          `
          UPDATE accounts
          SET
            access_key = $1,
            discord_username = $2,
            discord_global_name = $3,
            discord_avatar = $4,
            discord_email = $5,
            last_login_at = NOW()
          WHERE id = $6
          `,
          [
            newKey.key,
            discordUsername,
            discordGlobalName,
            discordAvatar,
            discordEmail,
            account.id
          ]
        );


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
            created_at,
            expires_at
          )
          VALUES
          (
            $1,
            $2,
            NOW(),
            $3
          )
          `,
          [
            sessionToken,
            account.id,
            expiresAt
          ]
        );


        return res.redirect(
          frontendRedirect({
            success:
              "true",

            sessionToken,

            accessKey:
              newKey.key,

            keyIssuedAt:
              Date.now(),

            username:
              account.username,

            discordId,

            discordUsername,

            discordEmail
          })
        );
      }


      /* ===================================================
         NEW DISCORD ACCOUNT
      =================================================== */

      const newKey =
        await createAccessKey(
          discordId
        );


      return res.redirect(
        frontendRedirect({
          success:
            "true",

          accessKey:
            newKey.key,

          keyIssuedAt:
            Date.now(),

          discordId,

          discordUsername,

          discordEmail
        })
      );

    } catch (error) {

      console.error(
        "❌ Discord callback error:",
        error
      );

      return res.redirect(
        frontendRedirect({
          discordError:
            "حدث خطأ أثناء تسجيل الدخول عبر Discord."
        })
      );
    }
  }
);


/* =========================================================
   REGISTER
========================================================= */

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


    if (
      !cleanName ||
      typeof password !==
        "string" ||
      typeof confirmPassword !==
        "string" ||
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


      const keyResult =
        await client.query(
          `
          SELECT
            id,
            key,
            discord_id,
            used,
            account_id
          FROM access_keys
          WHERE key = $1
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


      if (keyRow.used) {

        await client.query(
          "ROLLBACK"
        );

        return sendError(
          res,
          400,
          "هذا المفتاح مستعمل أو منتهي. ادخل Discord من جديد للحصول على مفتاح جديد."
        );
      }


      const usernameResult =
        await client.query(
          `
          SELECT id
          FROM accounts
          WHERE LOWER(username) = $1
          LIMIT 1
          `,
          [normalizedName]
        );


      if (
        usernameResult.rows.length > 0
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


      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );


      const accountResult =
        await client.query(
          `
          INSERT INTO accounts
          (
            username,
            password,
            access_key,
            discord_id,
            auth_provider,
            created_at
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            NOW()
          )
          RETURNING
            id,
            username,
            access_key,
            discord_id,
            created_at
          `,
          [
            cleanName,
            passwordHash,
            keyRow.key,
            keyRow.discord_id,
            keyRow.discord_id
              ? "discord"
              : "password"
          ]
        );


      const account =
        accountResult.rows[0];


      await client.query(
        `
        UPDATE access_keys
        SET
          used = TRUE,
          used_by = $1,
          account_id = $2,
          used_at = NOW()
        WHERE id = $3
        `,
        [
          account.username,
          account.id,
          keyRow.id
        ]
      );


      const sessionToken =
        generateSessionToken();


      const expiresAt =
        new Date(
          Date.now() +
          SESSION_MS
        );


      await client.query(
        `
        INSERT INTO sessions
        (
          token,
          user_id,
          created_at,
          expires_at
        )
        VALUES
        (
          $1,
          $2,
          NOW(),
          $3
        )
        `,
        [
          sessionToken,
          account.id,
          expiresAt
        ]
      );


      await client.query(
        "COMMIT"
      );


      console.log(
        "✅ Account created:",
        account.username
      );


      return res
        .status(201)
        .json({
          success: true,

          message:
            "تم إنشاء الحساب بنجاح.",

          sessionToken,

          accessKey:
            account.access_key,

          user: {
            id:
              account.id,

            username:
              account.username,

            accessKey:
              account.access_key,

            discordId:
              account.discord_id,

            createdAt:
              account.created_at
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
          "اسم المستخدم مستعمل من قبل."
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


/* =========================================================
   LOGIN
========================================================= */

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
        typeof password !==
          "string"
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
            password,
            access_key,
            discord_id,
            created_at
          FROM accounts
          WHERE LOWER(username) = $1
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


      const account =
        result.rows[0];


      if (
        !account.password
      ) {

        return sendError(
          res,
          401,
          "هذا الحساب لا يملك كلمة مرور."
        );
      }


      const passwordOK =
        await bcrypt.compare(
          password,
          account.password
        );


      if (!passwordOK) {

        return sendError(
          res,
          401,
          "اسم المستخدم أو كلمة المرور غير صحيحة."
        );
      }


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
          created_at,
          expires_at
        )
        VALUES
        (
          $1,
          $2,
          NOW(),
          $3
        )
        `,
        [
          sessionToken,
          account.id,
          expiresAt
        ]
      );


      await pool.query(
        `
        UPDATE accounts
        SET last_login_at = NOW()
        WHERE id = $1
        `,
        [account.id]
      );


      return res.json({
        success: true,

        message:
          "تم تسجيل الدخول بنجاح.",

        sessionToken,

        accessKey:
          account.access_key,

        user: {
          id:
            account.id,

          username:
            account.username,

          accessKey:
            account.access_key,

          discordId:
            account.discord_id,

          createdAt:
            account.created_at
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


/* =========================================================
   AUTHENTICATED USER
========================================================= */

async function getAuthenticatedUser(
  req
) {

  const authorization =
    req.headers.authorization ||
    "";


  if (
    !authorization.startsWith(
      "Bearer "
    )
  ) {

    return null;
  }


  const token =
    authorization
      .slice(7)
      .trim();


  if (!token) {
    return null;
  }


  const result =
    await pool.query(
      `
      SELECT
        a.id,
        a.username,
        a.access_key,
        a.discord_id,
        a.discord_username,
        a.discord_global_name,
        a.discord_avatar,
        a.discord_email,
        a.auth_provider,
        a.created_at,
        a.last_login_at
      FROM sessions s
      INNER JOIN accounts a
        ON a.id = s.user_id
      WHERE
        s.token = $1
        AND s.expires_at >
          CURRENT_TIMESTAMP
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


/* =========================================================
   USER
========================================================= */

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

          discordUsername:
            user.discord_username,

          discordGlobalName:
            user.discord_global_name,

          discordAvatar:
            user.discord_avatar,

          discordEmail:
            user.discord_email,

          authProvider:
            user.auth_provider,

          createdAt:
            user.created_at,

          lastLoginAt:
            user.last_login_at
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


/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/logout",
  async (req, res) => {

    try {

      const authorization =
        req.headers.authorization ||
        "";


      if (
        authorization.startsWith(
          "Bearer "
        )
      ) {

        const token =
          authorization
            .slice(7)
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


/* =========================================================
   ADMIN ACCESS KEYS
========================================================= */

app.get(
  "/api/admin/access-keys",
  async (req, res) => {

    try {

      if (!ADMIN_KEY) {

        return sendError(
          res,
          404,
          "Admin endpoint disabled."
        );
      }


      const providedKey =
        req.headers[
          "x-admin-key"
        ];


      if (
        typeof providedKey !==
          "string" ||
        providedKey !==
          ADMIN_KEY
      ) {

        return sendError(
          res,
          401,
          "Admin key غير صحيحة."
        );
      }


      const result =
        await pool.query(
          `
          SELECT
            id,
            key,
            used,
            used_by,
            account_id,
            discord_id,
            created_at,
            used_at
          FROM access_keys
          ORDER BY created_at DESC
          LIMIT 200
          `
        );


      return res.json({
        success: true,

        count:
          result.rows.length,

        keys:
          result.rows
      });

    } catch (error) {

      console.error(
        "❌ Admin error:",
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


/* =========================================================
   SESSION CLEANUP
========================================================= */

async function cleanupSessions() {

  try {

    const result =
      await pool.query(
        `
        DELETE FROM sessions
        WHERE expires_at <=
          CURRENT_TIMESTAMP
        `
      );


    if (
      result.rowCount > 0
    ) {

      console.log(
        "🧹 Expired sessions deleted:",
        result.rowCount
      );
    }

  } catch (error) {

    console.error(
      "❌ Session cleanup error:",
      error
    );
  }
}


/* =========================================================
   404
========================================================= */

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


/* =========================================================
   ERROR HANDLER
========================================================= */

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


    return res
      .status(500)
      .json({
        success: false,

        message:
          "حدث خطأ داخلي في السيرفر."
      });
  }
);


/* =========================================================
   START
========================================================= */

async function startServer() {

  try {

    if (
      missing.length > 0
    ) {

      console.error(
        "❌ Cannot start server."
      );

      console.error(
        "Missing:",
        missing.join(", ")
      );

      process.exit(1);
    }


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
            `🌐 Frontend URL: ${FRONTEND_URL}`
          );

          console.log(
            `🌐 CORS Origin: ${FRONTEND_ORIGIN}`
          );

          console.log(
            `🔗 Discord Callback: ${DISCORD_REDIRECT_URI}`
          );

          console.log(
            "🗄️ PostgreSQL: CONNECTED"
          );

          console.log(
            "🔑 NEW ACCESS KEY ON EVERY DISCORD LOGIN: ON"
          );

          console.log(
            "📧 DISCORD EMAIL: ON"
          );

          console.log(
            "🔐 SESSIONS: 30 DAYS"
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


/* =========================================================
   SHUTDOWN
========================================================= */

async function shutdown() {

  try {

    await pool.end();

  } catch (error) {

    console.error(
      "Shutdown error:",
      error
    );
  }

  process.exit(0);
}


process.on(
  "SIGTERM",
  shutdown
);

process.on(
  "SIGINT",
  shutdown
);


/* =========================================================
   START SERVER
========================================================= */

startServer();
