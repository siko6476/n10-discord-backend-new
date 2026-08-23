require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;

// ==================================================
// Environment Variables
// ==================================================

const DISCORD_CLIENT_ID =
  process.env.DISCORD_CLIENT_ID;

const DISCORD_CLIENT_SECRET =
  process.env.DISCORD_CLIENT_SECRET;

const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI;

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io/N10-SERVER-MENA/";

const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET;

const ADMIN_KEY =
  process.env.ADMIN_KEY;

const DATABASE_URL =
  process.env.DATABASE_URL;

// ==================================================
// التحقق من DATABASE_URL
// ==================================================

if (!DATABASE_URL) {
  console.error(
    "❌ DATABASE_URL غير موجود في Environment Variables"
  );

  process.exit(1);
}

// ==================================================
// PostgreSQL
// ==================================================

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl: {
    rejectUnauthorized: false
  },

  max: 10,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000
});

// ==================================================
// إنشاء الجداول
// ==================================================

async function initDatabase() {
  const client = await pool.connect();

  try {
    // ==============================================
    // Accounts
    // ==============================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,

        username VARCHAR(24) NOT NULL UNIQUE,

        password TEXT,

        access_key TEXT,

        discord_id TEXT UNIQUE,

        discord_username TEXT,

        discord_global_name TEXT,

        discord_avatar TEXT,

        auth_provider VARCHAR(20)
          DEFAULT 'password',

        created_at TIMESTAMPTZ
          DEFAULT NOW(),

        last_login_at TIMESTAMPTZ
      );
    `);

    // ==============================================
    // Access Keys
    // ==============================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS access_keys (
        id SERIAL PRIMARY KEY,

        key TEXT NOT NULL UNIQUE,

        used BOOLEAN DEFAULT FALSE,

        used_by TEXT,

        account_id INTEGER,

        discord_id TEXT,

        created_at TIMESTAMPTZ
          DEFAULT NOW(),

        used_at TIMESTAMPTZ
      );
    `);

    // ==============================================
    // Indexes
    // ==============================================

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_accounts_discord_id
      ON accounts(discord_id);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_accounts_username
      ON accounts(username);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_access_keys_account_id
      ON access_keys(account_id);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_access_keys_discord_id
      ON access_keys(discord_id);
    `);

    console.log(
      "✅ PostgreSQL database ready"
    );

  } finally {
    client.release();
  }
}

// ==================================================
// Middleware
// ==================================================

app.use(
  express.json({
    limit: "1mb"
  })
);

// ==================================================
// CORS
// ==================================================

app.use((req, res, next) => {
  res.header(
    "Access-Control-Allow-Origin",
    "*"
  );

  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Admin-Key"
  );

  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// ==================================================
// Health Check
// ==================================================

app.get(
  "/health",
  async (req, res) => {
    try {
      await pool.query(
        "SELECT 1"
      );

      res.json({
        success: true,
        ok: true,
        status: "online",
        database: "connected",
        service:
          "N10 Discord Backend",
        version: "4.0.0"
      });

    } catch (error) {
      console.error(
        "Health Error:",
        error
      );

      res.status(503).json({
        success: false,
        ok: false,
        status: "online",
        database:
          "disconnected"
      });
    }
  }
);

// ==================================================
// الصفحة الرئيسية
// ==================================================

app.get(
  "/",
  (req, res) => {
    res.json({
      success: true,
      service:
        "N10 Discord Backend",
      database:
        "PostgreSQL",
      message:
        "Backend is running"
    });
  }
);

// ==================================================
// OAuth State
// ==================================================

function createOAuthState() {
  if (!OAUTH_STATE_SECRET) {
    throw new Error(
      "OAUTH_STATE_SECRET غير موجود"
    );
  }

  const timestamp =
    Date.now().toString();

  const nonce =
    crypto
      .randomBytes(32)
      .toString("hex");

  const payload =
    `${timestamp}.${nonce}`;

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

// ==================================================
// Verify OAuth State
// ==================================================

function verifyOAuthState(state) {
  try {
    if (
      !state ||
      !OAUTH_STATE_SECRET
    ) {
      return false;
    }

    const parts =
      state.split(".");

    if (parts.length !== 3) {
      return false;
    }

    const timestamp =
      parts[0];

    const nonce =
      parts[1];

    const signature =
      parts[2];

    if (
      !timestamp ||
      !nonce ||
      !signature
    ) {
      return false;
    }

    const payload =
      `${timestamp}.${nonce}`;

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

    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
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
      age <= 10 * 60 * 1000
    );

  } catch (error) {
    console.error(
      "OAuth State Verify Error:",
      error
    );

    return false;
  }
}

// ==================================================
// Cookies
// ==================================================

function parseCookies(req) {
  const cookies = {};

  const header =
    req.headers.cookie;

  if (!header) {
    return cookies;
  }

  header
    .split(";")
    .forEach((part) => {
      const index =
        part.indexOf("=");

      if (index === -1) {
        return;
      }

      const name =
        part
          .slice(0, index)
          .trim();

      const value =
        part
          .slice(index + 1)
          .trim();

      try {
        cookies[name] =
          decodeURIComponent(
            value
          );
      } catch {
        cookies[name] =
          value;
      }
    });

  return cookies;
}

// ==================================================
// OAuth Cookie
// ==================================================

function setOAuthCookie(
  res,
  state
) {
  res.setHeader(
    "Set-Cookie",

    `n10_oauth_state=${encodeURIComponent(
      state
    )}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
  );
}

function clearOAuthCookie(res) {
  res.setHeader(
    "Set-Cookie",

    "n10_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  );
}

// ==================================================
// Generate Access Key
// ==================================================

function generateAccessKey() {
  return (
    "N10-" +
    crypto
      .randomBytes(16)
      .toString("hex")
  );
}

// ==================================================
// إنشاء مفتاح جديد للحساب
// ==================================================

async function createKeyForAccount(
  client,
  accountId,
  username,
  discordId = null
) {
  const key =
    generateAccessKey();

  await client.query(
    `
    INSERT INTO access_keys (
      key,
      used,
      used_by,
      account_id,
      discord_id,
      created_at,
      used_at
    )
    VALUES (
      $1,
      TRUE,
      $2,
      $3,
      $4,
      NOW(),
      NOW()
    )
    `,
    [
      key,
      username,
      accountId,
      discordId
    ]
  );

  // نخلي آخر مفتاح في الحساب
  await client.query(
    `
    UPDATE accounts
    SET access_key = $1
    WHERE id = $2
    `,
    [
      key,
      accountId
    ]
  );

  return key;
}

// ==================================================
// Discord Login
// ==================================================

app.get(
  "/auth/discord",
  (req, res) => {
    if (
      !DISCORD_CLIENT_ID ||
      !DISCORD_CLIENT_SECRET ||
      !DISCORD_REDIRECT_URI ||
      !OAUTH_STATE_SECRET
    ) {
      return res.status(500).send(
        "Discord OAuth غير مضبوط في Render. تأكد من Environment Variables."
      );
    }

    try {
      const state =
        createOAuthState();

      setOAuthCookie(
        res,
        state
      );

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
        `https://discord.com/oauth2/authorize?${params.toString()}`
      );

    } catch (error) {
      console.error(
        "Discord Start Error:",
        error
      );

      return res.status(500).send(
        "تعذر بدء تسجيل الدخول عبر Discord."
      );
    }
  }
);

// ==================================================
// Discord Callback
// ==================================================

app.get(
  "/auth/discord/callback",
  async (req, res) => {
    try {
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

      // ============================================
      // Discord Cancel
      // ============================================

      if (discordError) {
        clearOAuthCookie(res);

        return res.redirect(
          `${FRONTEND_URL}?discordError=${encodeURIComponent(
            "تم إلغاء تسجيل الدخول عبر Discord"
          )}`
        );
      }

      // ============================================
      // Code / State
      // ============================================

      if (!code || !state) {
        return res.status(400).send(
          "Discord لم يرسل Code أو State."
        );
      }

      // ============================================
      // Cookie
      // ============================================

      const cookies =
        parseCookies(req);

      const savedState =
        cookies.n10_oauth_state ||
        "";

      if (
        !savedState ||
        savedState !== state ||
        !verifyOAuthState(
          state
        )
      ) {
        clearOAuthCookie(res);

        return res.status(400).send(
          "OAuth State غير صالح أو منتهي. أعد تسجيل الدخول من الموقع."
        );
      }

      clearOAuthCookie(res);

      // ============================================
      // Token
      // ============================================

      const tokenBody =
        new URLSearchParams({
          grant_type:
            "authorization_code",

          code,

          redirect_uri:
            DISCORD_REDIRECT_URI
        });

      const tokenResponse =
        await fetch(
          "https://discord.com/api/oauth2/token",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded",

              Accept:
                "application/json",

              Authorization:
                "Basic " +
                Buffer.from(
                  `${DISCORD_CLIENT_ID}:${DISCORD_CLIENT_SECRET}`
                ).toString("base64")
            },

            body:
              tokenBody.toString()
          }
        );

      const tokenData =
        await tokenResponse.json();

      if (
        !tokenResponse.ok ||
        !tokenData.access_token
      ) {
        console.error(
          "Discord Token Error:",
          tokenData
        );

        return res.status(502).send(
          "فشل الاتصال بـ Discord أثناء تسجيل الدخول."
        );
      }

      // ============================================
      // Discord User
      // ============================================

      const userResponse =
        await fetch(
          "https://discord.com/api/users/@me",
          {
            method: "GET",

            headers: {
              Authorization:
                `Bearer ${tokenData.access_token}`,

              Accept:
                "application/json"
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
          "Discord User Error:",
          discordUser
        );

        return res.status(502).send(
          "تعذر الحصول على معلومات حساب Discord."
        );
      }

      // ============================================
      // Transaction
      // ============================================

      const client =
        await pool.connect();

      try {
        await client.query(
          "BEGIN"
        );

        // ==========================================
        // البحث عن الحساب
        // ==========================================

        const existing =
          await client.query(
            `
            SELECT *
            FROM accounts
            WHERE discord_id = $1
            LIMIT 1
            `,
            [
              discordUser.id
            ]
          );

        let accountId;
        let username;

        // ==========================================
        // الحساب موجود
        // ==========================================

        if (
          existing.rows.length > 0
        ) {
          const account =
            existing.rows[0];

          accountId =
            account.id;

          username =
            account.username;

          await client.query(
            `
            UPDATE accounts
            SET
              discord_username = $1,
              discord_global_name = $2,
              discord_avatar = $3,
              last_login_at = NOW()
            WHERE id = $4
            `,
            [
              discordUser.username ||
                null,

              discordUser.global_name ||
                null,

              discordUser.avatar ||
                null,

              account.id
            ]
          );

          console.log(
            "♻️ Existing Discord account:",
            username
          );

        } else {

          // ========================================
          // حساب Discord جديد
          // ========================================

          const rawName =
            (
              discordUser.global_name ||
              discordUser.username ||
              `discord_${discordUser.id}`
            )
              .trim();

          const baseUsername =
            rawName
              .replace(
                /[^a-zA-Z0-9_-]/g,
                "_"
              )
              .slice(0, 20) ||
            `discord_${discordUser.id}`;

          username =
            baseUsername;

          let counter = 1;

          while (true) {
            const check =
              await client.query(
                `
                SELECT id
                FROM accounts
                WHERE LOWER(username) = LOWER($1)
                LIMIT 1
                `,
                [username]
              );

            if (
              check.rows.length === 0
            ) {
              break;
            }

            username =
              `${baseUsername}_${counter}`
                .slice(0, 24);

            counter++;
          }

          // ========================================
          // Random Password
          // ========================================

          const randomPassword =
            crypto
              .randomBytes(32)
              .toString("hex");

          const passwordHash =
            await bcrypt.hash(
              randomPassword,
              12
            );

          // ========================================
          // Create Account
          // ========================================

          const accountResult =
            await client.query(
              `
              INSERT INTO accounts (
                username,
                password,
                discord_id,
                discord_username,
                discord_global_name,
                discord_avatar,
                auth_provider,
                created_at,
                last_login_at
              )
              VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                'discord',
                NOW(),
                NOW()
              )
              RETURNING id
              `,
              [
                username,

                passwordHash,

                discordUser.id,

                discordUser.username ||
                  null,

                discordUser.global_name ||
                  null,

                discordUser.avatar ||
                  null
              ]
            );

          accountId =
            accountResult.rows[0].id;

          console.log(
            "🆕 New Discord account:",
            username
          );
        }

        // ==========================================
        // IMPORTANT:
        // كل دخول Discord يولد Key جديد
        // ==========================================

        const newKey =
          await createKeyForAccount(
            client,
            accountId,
            username,
            discordUser.id
          );

        await client.query(
          "COMMIT"
        );

        console.log(
          "🔑 New key generated:",
          newKey
        );

        // ==========================================
        // Redirect
        // ==========================================

        return res.redirect(
          `${FRONTEND_URL}?accessKey=${encodeURIComponent(
            newKey
          )}&username=${encodeURIComponent(
            username
          )}&login=success`
        );

      } catch (error) {

        await client.query(
          "ROLLBACK"
        );

        console.error(
          "Discord Transaction Error:",
          error
        );

        return res.status(500).send(
          "تعذر حفظ حساب Discord أو إنشاء المفتاح."
        );

      } finally {
        client.release();
      }

    } catch (error) {

      console.error(
        "Discord OAuth Error:",
        error
      );

      return res.status(500).send(
        "حدث خطأ داخلي أثناء تسجيل الدخول عبر Discord."
      );
    }
  }
);

// ==================================================
// Admin Generate Key
// ==================================================

async function createAccessKey(
  req,
  res
) {
  try {

    const provided =
      typeof req.body?.adminKey ===
      "string"
        ? req.body.adminKey.trim()
        : "";

    if (
      !ADMIN_KEY ||
      !provided ||
      provided !== ADMIN_KEY
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Unauthorized"
      });
    }

    const key =
      generateAccessKey();

    const result =
      await pool.query(
        `
        INSERT INTO access_keys (
          key,
          used
        )
        VALUES (
          $1,
          FALSE
        )
        RETURNING *
        `,
        [key]
      );

    return res.status(201).json({
      success: true,
      accessKey:
        result.rows[0].key,
      used: false
    });

  } catch (error) {

    console.error(
      "Create Key Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Internal server error"
    });
  }
}

app.post(
  "/admin/create-key",
  createAccessKey
);

app.post(
  "/api/admin/create-key",
  createAccessKey
);

// ==================================================
// Register
// ==================================================

async function register(
  req,
  res
) {
  try {

    const username =
      typeof req.body?.username ===
      "string"
        ? req.body.username.trim()
        : "";

    const password =
      typeof req.body?.password ===
      "string"
        ? req.body.password
        : "";

    const accessKey =
      typeof req.body?.accessKey ===
      "string"
        ? req.body.accessKey.trim()
        : "";

    if (
      !username ||
      !password ||
      !accessKey
    ) {
      return res.status(400).json({
        success: false,
        message:
          "اسم المستخدم وكلمة المرور و Access Key مطلوبة"
      });
    }

    if (
      username.length < 3 ||
      username.length > 24
    ) {
      return res.status(400).json({
        success: false,
        message:
          "اسم المستخدم يجب أن يكون بين 3 و24 حرفاً"
      });
    }

    if (
      password.length < 6
    ) {
      return res.status(400).json({
        success: false,
        message:
          "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
      });
    }

    // ============================================
    // Username Check
    // ============================================

    const usernameCheck =
      await pool.query(
        `
        SELECT id
        FROM accounts
        WHERE LOWER(username) = LOWER($1)
        LIMIT 1
        `,
        [username]
      );

    if (
      usernameCheck.rows.length > 0
    ) {
      return res.status(409).json({
        success: false,
        message:
          "اسم المستخدم موجود بالفعل"
      });
    }

    // ============================================
    // Key Check
    // ============================================

    const keyCheck =
      await pool.query(
        `
        SELECT *
        FROM access_keys
        WHERE key = $1
        AND used = FALSE
        LIMIT 1
        `,
        [accessKey]
      );

    if (
      keyCheck.rows.length === 0
    ) {
      return res.status(403).json({
        success: false,
        message:
          "Access Key غير صالح أو مستعمل"
      });
    }

    // ============================================
    // Password Hash
    // ============================================

    const passwordHash =
      await bcrypt.hash(
        password,
        12
      );

    const client =
      await pool.connect();

    try {

      await client.query(
        "BEGIN"
      );

      // ==========================================
      // Create Account
      // ==========================================

      const accountResult =
        await client.query(
          `
          INSERT INTO accounts (
            username,
            password,
            access_key,
            auth_provider,
            created_at
          )
          VALUES (
            $1,
            $2,
            $3,
            'password',
            NOW()
          )
          RETURNING id
          `,
          [
            username,
            passwordHash,
            accessKey
          ]
        );

      const accountId =
        accountResult.rows[0].id;

      // ==========================================
      // استعمال المفتاح
      // ==========================================

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
          username,
          accountId,
          keyCheck.rows[0].id
        ]
      );

      await client.query(
        "COMMIT"
      );

      return res.status(201).json({
        success: true,
        message:
          "Account created successfully",

        user: {
          username,
          accessKey
        }
      });

    } catch (error) {

      await client.query(
        "ROLLBACK"
      );

      console.error(
        "Register Transaction Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to save account"
      });

    } finally {
      client.release();
    }

  } catch (error) {

    console.error(
      "Register Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Internal server error"
    });
  }
}

app.post(
  "/register",
  register
);

app.post(
  "/api/register",
  register
);

// ==================================================
// Login Username / Password
// ==================================================

async function login(
  req,
  res
) {
  try {

    const username =
      typeof req.body?.username ===
      "string"
        ? req.body.username.trim()
        : "";

    const password =
      typeof req.body?.password ===
      "string"
        ? req.body.password
        : "";

    if (
      !username ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Username and password are required"
      });
    }

    // ============================================
    // Find Account
    // ============================================

    const result =
      await pool.query(
        `
        SELECT *
        FROM accounts
        WHERE LOWER(username) = LOWER($1)
        LIMIT 1
        `,
        [username]
      );

    if (
      result.rows.length === 0
    ) {
      return res.status(401).json({
        success: false,
        message:
          "اسم المستخدم أو كلمة المرور غير صحيحة"
      });
    }

    const account =
      result.rows[0];

    // ============================================
    // Discord Account
    // ============================================

    if (
      account.auth_provider ===
        "discord" &&
      account.discord_id
    ) {
      return res.status(403).json({
        success: false,
        message:
          "هذا الحساب مرتبط بـ Discord. استعمل تسجيل الدخول عبر Discord."
      });
    }

    if (
      !account.password
    ) {
      return res.status(401).json({
        success: false,
        message:
          "اسم المستخدم أو كلمة المرور غير صحيحة"
      });
    }

    // ============================================
    // Compare Password
    // ============================================

    const correct =
      await bcrypt.compare(
        password,
        account.password
      );

    if (!correct) {
      return res.status(401).json({
        success: false,
        message:
          "اسم المستخدم أو كلمة المرور غير صحيحة"
      });
    }

    // ============================================
    // Update Login
    // ============================================

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
        "Login successful",

      user: {
        username:
          account.username,

        accessKey:
          account.access_key ||
          null
      },

      accessKey:
        account.access_key ||
        null
    });

  } catch (error) {

    console.error(
      "Login Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Internal server error"
    });
  }
}

app.post(
  "/login",
  login
);

app.post(
  "/api/login",
  login
);

// ==================================================
// Generate Key For Existing Account
// ==================================================

async function generateAccountKey(
  req,
  res
) {
  try {

    const username =
      typeof req.body?.username ===
      "string"
        ? req.body.username.trim()
        : "";

    if (!username) {
      return res.status(400).json({
        success: false,
        message:
          "Username is required"
      });
    }

    const result =
      await pool.query(
        `
        SELECT *
        FROM accounts
        WHERE LOWER(username) = LOWER($1)
        LIMIT 1
        `,
        [username]
      );

    if (
      result.rows.length === 0
    ) {
      return res.status(404).json({
        success: false,
        message:
          "الحساب غير موجود"
      });
    }

    const account =
      result.rows[0];

    const key =
      generateAccessKey();

    await pool.query(
      `
      INSERT INTO access_keys (
        key,
        used,
        used_by,
        account_id,
        discord_id,
        created_at,
        used_at
      )
      VALUES (
        $1,
        TRUE,
        $2,
        $3,
        $4,
        NOW(),
        NOW()
      )
      `,
      [
        key,

        account.username,

        account.id,

        account.discord_id ||
          null
      ]
    );

    await pool.query(
      `
      UPDATE accounts
      SET access_key = $1
      WHERE id = $2
      `,
      [
        key,
        account.id
      ]
    );

    return res.json({
      success: true,
      message:
        "New key generated",

      accessKey:
        key
    });

  } catch (error) {

    console.error(
      "Generate Account Key Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Internal server error"
    });
  }
}

app.post(
  "/api/account/generate-key",
  generateAccountKey
);

app.post(
  "/account/generate-key",
  generateAccountKey
);

// ==================================================
// Admin Stats
// ==================================================

app.get(
  "/admin/stats",
  async (req, res) => {
    try {

      const adminKey =
        req.headers[
          "x-admin-key"
        ];

      if (
        !adminKey ||
        adminKey !== ADMIN_KEY
      ) {
        return res.status(401).json({
          success: false,
          message:
            "Unauthorized"
        });
      }

      const accounts =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM accounts
          `
        );

      const keys =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM access_keys
          `
        );

      return res.json({
        success: true,

        accounts:
          accounts.rows[0].count,

        keys:
          keys.rows[0].count
      });

    } catch (error) {

      console.error(
        "Stats Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Internal server error"
      });
    }
  }
);

// ==================================================
// 404
// ==================================================

app.use(
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        `Route not found: ${req.method} ${req.originalUrl}`
    });
  }
);

// ==================================================
// Error Handler
// ==================================================

app.use(
  (
    err,
    req,
    res,
    next
  ) => {

    console.error(
      "Server Error:",
      err
    );

    res.status(500).json({
      success: false,
      message:
        "Internal server error"
    });
  }
);

// ==================================================
// Start Server
// ==================================================

async function startServer() {
  try {

    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `🚀 N10 Discord Backend running on port ${PORT}`
        );

        console.log(
          "❤️ Health: /health"
        );

        console.log(
          "🎮 Discord OAuth: /auth/discord"
        );

        console.log(
          "🔐 Discord Callback: /auth/discord/callback"
        );

        console.log(
          "🔑 Admin Create Key: /admin/create-key"
        );

        console.log(
          "👤 Account Generate Key: /api/account/generate-key"
        );
      }
    );

  } catch (error) {

    console.error(
      "❌ Database startup error:",
      error
    );

    process.exit(1);
  }
}

startServer();
