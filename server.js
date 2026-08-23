"use strict";

/*
========================================================
 N10 SERVER MENA
 Backend كامل:
 - Discord OAuth2
 - Access Keys
 - Register
 - Login
 - PostgreSQL
 - CORS
 - Password hashing
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
 الإعدادات
========================================================
*/

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io";

const DISCORD_CLIENT_ID =
  process.env.DISCORD_CLIENT_ID;

const DISCORD_CLIENT_SECRET =
  process.env.DISCORD_CLIENT_SECRET;

const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI ||
  `https://n10-discord-backend-new.onrender.com/auth/discord/callback`;

const DATABASE_URL =
  process.env.DATABASE_URL;

/*
========================================================
 التحقق من Environment Variables
========================================================
*/

if (!DATABASE_URL) {
  console.error("❌ DATABASE_URL غير موجود.");
}

if (!DISCORD_CLIENT_ID) {
  console.error("❌ DISCORD_CLIENT_ID غير موجود.");
}

if (!DISCORD_CLIENT_SECRET) {
  console.error("❌ DISCORD_CLIENT_SECRET غير موجود.");
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
      : false
});

/*
========================================================
 Middleware
========================================================
*/

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.urlencoded({
    extended: true
  })
);

/*
========================================================
 وظائف مساعدة
========================================================
*/

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function normalizeUsername(username) {
  return String(username || "")
    .trim()
    .toLowerCase();
}

function cleanUsername(username) {
  return String(username || "").trim();
}

function validUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,24}$/.test(username);
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 6
  );
}

function validAccessKey(key) {
  return (
    typeof key === "string" &&
    /^N10-[A-Za-z0-9]+$/.test(key)
  );
}

/*
========================================================
 إنشاء Access Key
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
 إنشاء Session بسيطة
========================================================
*/

function generateSessionToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

/*
========================================================
 تهيئة قاعدة البيانات
========================================================
*/

async function initDatabase() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    /*
    -----------------------------------------------
    users
    -----------------------------------------------
    */

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(24) NOT NULL,
        username_normalized VARCHAR(24) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        access_key TEXT UNIQUE NOT NULL,
        discord_id TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    /*
    -----------------------------------------------
    access_keys
    -----------------------------------------------
    */

    await client.query(`
      CREATE TABLE IF NOT EXISTS access_keys (
        id SERIAL PRIMARY KEY,
        access_key TEXT UNIQUE NOT NULL,
        discord_id TEXT,
        used BOOLEAN NOT NULL DEFAULT FALSE,
        used_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        used_at TIMESTAMP
      )
    `);

    /*
    -----------------------------------------------
    sessions
    -----------------------------------------------
    */

    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        token TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query("COMMIT");

    console.log("✅ PostgreSQL database جاهزة.");
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
 الصفحة الرئيسية للسيرفر
========================================================
*/

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "N10 SERVER MENA",
    status: "online"
  });
});

/*
========================================================
 Health Check
========================================================
*/

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      status: "online",
      database: "connected"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      status: "online",
      database: "error"
    });
  }
});

/*
========================================================
 Discord OAuth
========================================================
*/

app.get("/auth/discord", (req, res) => {
  if (
    !DISCORD_CLIENT_ID ||
    !DISCORD_CLIENT_SECRET
  ) {
    return sendError(
      res,
      500,
      "إعدادات Discord ناقصة في السيرفر."
    );
  }

  const params =
    new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      response_type: "code",
      redirect_uri: DISCORD_REDIRECT_URI,
      scope: "identify"
    });

  const discordURL =
    "https://discord.com/oauth2/authorize?" +
    params.toString();

  res.redirect(discordURL);
});

/*
========================================================
 Discord Callback
========================================================
*/

app.get(
  "/auth/discord/callback",
  async (req, res) => {
    try {
      const code = req.query.code;

      if (!code) {
        return res.redirect(
          `${FRONTEND_URL}/?error=discord_cancelled`
        );
      }

      /*
      -----------------------------------------------
      الحصول على OAuth Token
      -----------------------------------------------
      */

      const tokenResponse =
        await fetch(
          "https://discord.com/api/oauth2/token",
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
          `${FRONTEND_URL}/?error=discord_token_error`
        );
      }

      /*
      -----------------------------------------------
      معلومات Discord
      -----------------------------------------------
      */

      const userResponse =
        await fetch(
          "https://discord.com/api/users/@me",
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
          "Discord user error:",
          discordUser
        );

        return res.redirect(
          `${FRONTEND_URL}/?error=discord_user_error`
        );
      }

      const discordId =
        String(discordUser.id);

      /*
      -----------------------------------------------
      إذا عنده حساب مسبقاً
      -----------------------------------------------
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

      if (existingUser.rows.length > 0) {
        const user =
          existingUser.rows[0];

        /*
        المستخدم عنده حساب.
        نرجعه مباشرة بمفتاحه القديم.
        */

        return res.redirect(
          `${FRONTEND_URL}/?accessKey=${encodeURIComponent(
            user.access_key
          )}`
        );
      }

      /*
      -----------------------------------------------
      إنشاء Access Key جديد
      -----------------------------------------------

      مهم جداً:

      هنا المفتاح يبقى used = FALSE

      ما نعلّموهش مستعمل هنا.
      */

      let accessKey = null;

      for (let i = 0; i < 10; i++) {
        const candidate =
          generateAccessKey();

        const exists =
          await pool.query(
            `
            SELECT id
            FROM access_keys
            WHERE access_key = $1
            LIMIT 1
            `,
            [candidate]
          );

        if (exists.rows.length === 0) {
          accessKey = candidate;
          break;
        }
      }

      if (!accessKey) {
        return res.redirect(
          `${FRONTEND_URL}/?error=key_generation_failed`
        );
      }

      /*
      -----------------------------------------------
      حفظ المفتاح كـ UNUSED
      -----------------------------------------------
      */

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
          accessKey,
          discordId
        ]
      );

      /*
      -----------------------------------------------
      إرسال المستخدم إلى صفحة التسجيل
      -----------------------------------------------
      */

      return res.redirect(
        `${FRONTEND_URL}/?accessKey=${encodeURIComponent(
          accessKey
        )}`
      );
    } catch (error) {
      console.error(
        "❌ Discord callback error:",
        error
      );

      return res.redirect(
        `${FRONTEND_URL}/?error=discord_error`
      );
    }
  }
);

/*
========================================================
 REGISTER
========================================================

المفتاح يصبح USED هنا فقط.

ليس عند Discord.
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
      String(accessKey || "").trim();

    /*
    -----------------------------------------------
    التحقق
    -----------------------------------------------
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

    if (!validUsername(cleanName)) {
      return sendError(
        res,
        400,
        "اسم المستخدم يجب أن يحتوي على 3 إلى 24 حرفاً، ويمكن استعمال الأرقام و _ و - و ."
      );
    }

    if (!validPassword(password)) {
      return sendError(
        res,
        400,
        "كلمة المرور يجب أن تحتوي على 6 أحرف على الأقل."
      );
    }

    if (
      password !== confirmPassword
    ) {
      return sendError(
        res,
        400,
        "كلمتا المرور غير متطابقتين."
      );
    }

    if (!validAccessKey(key)) {
      return sendError(
        res,
        400,
        "Access Key غير صالح."
      );
    }

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      /*
      -----------------------------------------------
      التحقق من اسم المستخدم
      -----------------------------------------------
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
        await client.query("ROLLBACK");

        return sendError(
          res,
          409,
          "اسم المستخدم مستعمل من قبل."
        );
      }

      /*
      -----------------------------------------------
      التحقق من Access Key
      -----------------------------------------------
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

      if (keyResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return sendError(
          res,
          400,
          "Access Key غير صالح أو غير موجود."
        );
      }

      const keyRow =
        keyResult.rows[0];

      /*
      -----------------------------------------------
      أهم إصلاح
      -----------------------------------------------

      المفتاح الذي خرج من Discord يكون:

      used = FALSE

      لذلك التسجيل يسمح به.

      بعد نجاح إنشاء الحساب فقط:

      used = TRUE
      */

      if (keyRow.used === true) {
        await client.query("ROLLBACK");

        return sendError(
          res,
          400,
          "Access Key غير صالح أو مستعمل."
        );
      }

      /*
      -----------------------------------------------
      تشفير كلمة المرور
      -----------------------------------------------
      */

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      /*
      -----------------------------------------------
      إنشاء المستخدم
      -----------------------------------------------
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
      -----------------------------------------------
      الآن فقط يصبح المفتاح مستعملاً
      -----------------------------------------------
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

      await client.query("COMMIT");

      /*
      -----------------------------------------------
      نجاح
      -----------------------------------------------
      */

      return res.status(201).json({
        success: true,
        message:
          "تم إنشاء الحساب بنجاح.",
        user: {
          id: user.id,
          username: user.username,
          accessKey: user.access_key
        }
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(
        "❌ Register error:",
        error
      );

      /*
      معالجة duplicate
      */

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

      const cleanName =
        cleanUsername(username);

      const normalizedName =
        normalizeUsername(username);

      if (!cleanName || !password) {
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

      if (result.rows.length === 0) {
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
      -----------------------------------------------
      Session Token
      -----------------------------------------------
      */

      const sessionToken =
        generateSessionToken();

      await pool.query(
        `
        INSERT INTO sessions
          (
            token,
            user_id
          )
        VALUES
          ($1, $2)
        `,
        [
          sessionToken,
          user.id
        ]
      );

      /*
      -----------------------------------------------
      الرد
      -----------------------------------------------
      */

      return res.json({
        success: true,

        message:
          "تم تسجيل الدخول بنجاح.",

        token:
          sessionToken,

        accessKey:
          user.access_key,

        user: {
          id: user.id,
          username: user.username,
          accessKey: user.access_key,
          discordId: user.discord_id,
          createdAt: user.created_at
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

      if (!auth.startsWith("Bearer ")) {
        return sendError(
          res,
          401,
          "غير مصرح."
        );
      }

      const token =
        auth.substring(7).trim();

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
          WHERE s.token = $1
          LIMIT 1
          `,
          [token]
        );

      if (result.rows.length === 0) {
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
          username: user.username,
          accessKey: user.access_key,
          discordId: user.discord_id,
          createdAt: user.created_at
        }
      });
    } catch (error) {
      console.error(error);

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

      if (auth.startsWith("Bearer ")) {
        const token =
          auth.substring(7).trim();

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
      console.error(error);

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
 404
========================================================
*/

app.use(
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        "المسار غير موجود.",
      path: req.path
    });
  }
);

/*
========================================================
 أخطاء السيرفر
========================================================
*/

app.use(
  (error, req, res, next) => {
    console.error(
      "❌ Unhandled error:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "حدث خطأ داخلي في السيرفر."
    });
  }
);

/*
========================================================
 تشغيل السيرفر
========================================================
*/

async function startServer() {
  try {
    await initDatabase();

    app.listen(
      PORT,
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
