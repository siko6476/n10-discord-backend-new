require("dotenv").config();

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();

const PORT = process.env.PORT || 3000;

// ==================================================
// إعدادات Discord
// ==================================================

const DISCORD_CLIENT_ID =
  process.env.DISCORD_CLIENT_ID;

const DISCORD_CLIENT_SECRET =
  process.env.DISCORD_CLIENT_SECRET;

const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI ||
  "https://n10-discord-backend-new.onrender.com/auth/discord/callback";

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io/N10/";

const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET ||
  process.env.SESSION_SECRET;

// ==================================================
// ملفات البيانات
// ==================================================

const ACCOUNTS_FILE =
  path.join(__dirname, "accounts.json");

const KEYS_FILE =
  path.join(__dirname, "keys.json");

const INDEX_FILE =
  path.join(__dirname, "index.html");

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
    "Origin, X-Requested-With, Content-Type, Accept"
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
// إنشاء ملفات JSON إذا لم تكن موجودة
// ==================================================

function ensureFile(file) {

  try {

    if (!fs.existsSync(file)) {

      fs.writeFileSync(
        file,
        "[]",
        "utf8"
      );

      console.log(
        `Created: ${path.basename(file)}`
      );
    }

  } catch (error) {

    console.error(
      `Failed to create ${path.basename(file)}:`,
      error
    );

  }
}

ensureFile(ACCOUNTS_FILE);
ensureFile(KEYS_FILE);

// ==================================================
// قراءة JSON
// ==================================================

function readJSON(file) {

  try {

    if (!fs.existsSync(file)) {
      return [];
    }

    const content =
      fs
        .readFileSync(file, "utf8")
        .trim();

    if (!content) {
      return [];
    }

    const data =
      JSON.parse(content);

    return Array.isArray(data)
      ? data
      : [];

  } catch (error) {

    console.error(
      `Error reading ${path.basename(file)}:`,
      error
    );

    return [];
  }
}

// ==================================================
// كتابة JSON
// ==================================================

function writeJSON(file, data) {

  try {

    fs.writeFileSync(
      file,
      JSON.stringify(
        data,
        null,
        2
      ),
      "utf8"
    );

    return true;

  } catch (error) {

    console.error(
      `Error writing ${path.basename(file)}:`,
      error
    );

    return false;
  }
}

// ==================================================
// الصفحة الرئيسية
// ==================================================

app.get("/", (req, res) => {

  if (!fs.existsSync(INDEX_FILE)) {

    return res.status(500).json({
      success: false,
      message: "index.html is missing"
    });

  }

  res.sendFile(INDEX_FILE);

});

// ==================================================
// Health Check
// ==================================================

app.get("/health", (req, res) => {

  res.json({

    success: true,

    ok: true,

    status: "online",

    service:
      "N10 Discord Backend",

    version:
      "2.0.0"

  });

});

// ==================================================
// Discord OAuth - التحقق من الإعدادات
// ==================================================

function discordConfigReady() {

  return Boolean(

    DISCORD_CLIENT_ID &&
    DISCORD_CLIENT_SECRET &&
    DISCORD_REDIRECT_URI &&
    OAUTH_STATE_SECRET

  );

}

// ==================================================
// قراءة Cookies
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

      cookies[name] =
        decodeURIComponent(value);

    });

  return cookies;
}

// ==================================================
// إنشاء Cookie للـ OAuth State
// ==================================================

function setOAuthStateCookie(
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

// ==================================================
// حذف OAuth Cookie
// ==================================================

function clearOAuthStateCookie(res) {

  res.setHeader(
    "Set-Cookie",

    "n10_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"

  );

}

// ==================================================
// إنشاء OAuth State
// ==================================================

function createOAuthState() {

  const nonce =
    crypto.randomBytes(32).toString(
      "hex"
    );

  const timestamp =
    Date.now().toString();

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
// التحقق من OAuth State
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

    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          OAUTH_STATE_SECRET
        )
        .update(payload)
        .digest("hex");

    const providedBuffer =
      Buffer.from(
        signature,
        "utf8"
      );

    const expectedBuffer =
      Buffer.from(
        expectedSignature,
        "utf8"
      );

    if (
      providedBuffer.length !==
      expectedBuffer.length
    ) {
      return false;
    }

    if (
      !crypto.timingSafeEqual(
        providedBuffer,
        expectedBuffer
      )
    ) {
      return false;
    }

    const createdAt =
      Number(timestamp);

    if (
      !Number.isFinite(createdAt)
    ) {
      return false;
    }

    const age =
      Date.now() - createdAt;

    // صلاحية State = 10 دقائق
    if (
      age < 0 ||
      age > 10 * 60 * 1000
    ) {
      return false;
    }

    return true;

  } catch (error) {

    console.error(
      "OAuth State Error:",
      error
    );

    return false;
  }

}

// ==================================================
// Discord Login
// ==================================================

app.get(
  "/auth/discord",
  (req, res) => {

    if (!discordConfigReady()) {

      return res.status(500).send(

        "Discord OAuth غير مضبوط في Render. تأكد من DISCORD_CLIENT_ID و DISCORD_CLIENT_SECRET و DISCORD_REDIRECT_URI و OAUTH_STATE_SECRET."

      );

    }

    const state =
      createOAuthState();

    setOAuthStateCookie(
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

        state:
          state

      });

    const discordAuthorizeUrl =
      `https://discord.com/oauth2/authorize?${params.toString()}`;

    return res.redirect(
      discordAuthorizeUrl
    );

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

      const returnedState =
        typeof req.query.state ===
        "string"
          ? req.query.state
          : "";

      const discordError =
        typeof req.query.error ===
        "string"
          ? req.query.error
          : "";

      // المستخدم ألغى Discord
      if (discordError) {

        clearOAuthStateCookie(
          res
        );

        return res.redirect(

          `${FRONTEND_URL}?discordError=${encodeURIComponent(
            "تم إلغاء تسجيل الدخول عبر Discord"
          )}`

        );

      }

      if (!code) {

        return res.status(400).send(
          "Discord لم يرسل Authorization Code."
        );

      }

      const cookies =
        parseCookies(req);

      const savedState =
        cookies.n10_oauth_state ||
        "";

      // التحقق من State
      if (

        !savedState ||
        !returnedState ||
        savedState !==
          returnedState ||
        !verifyOAuthState(
          returnedState
        )

      ) {

        clearOAuthStateCookie(
          res
        );

        return res.status(400).send(

          "OAuth State غير صالح أو منتهي. أعد محاولة تسجيل الدخول من الموقع."

        );

      }

      clearOAuthStateCookie(
        res
      );

      // ==================================================
      // تحويل Code إلى Access Token
      // ==================================================

      const tokenBody =
        new URLSearchParams({

          grant_type:
            "authorization_code",

          code:
            code,

          redirect_uri:
            DISCORD_REDIRECT_URI

        });

      const tokenResponse =
        await fetch(

          "https://discord.com/api/oauth2/token",

          {

            method:
              "POST",

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

      // ==================================================
      // جلب معلومات مستخدم Discord
      // ==================================================

      const userResponse =
        await fetch(

          "https://discord.com/api/users/@me",

          {

            method:
              "GET",

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

      // ==================================================
      // قراءة الحسابات والمفاتيح
      // ==================================================

      const accounts =
        readJSON(
          ACCOUNTS_FILE
        );

      const keys =
        readJSON(
          KEYS_FILE
        );

      // ==================================================
      // البحث عن Discord ID
      // ==================================================

      const accountIndex =
        accounts.findIndex(

          (account) =>

            account &&
            account.discordId ===
              discordUser.id

        );

      // ==================================================
      // الحساب موجود
      // ==================================================

      if (
        accountIndex !== -1
      ) {

        const account =
          accounts[
            accountIndex
          ];

        account.discordUsername =
          discordUser.username ||
          null;

        account.discordGlobalName =
          discordUser.global_name ||
          null;

        account.discordAvatar =
          discordUser.avatar ||
          null;

        account.lastLoginAt =
          new Date().toISOString();

        const saved =
          writeJSON(
            ACCOUNTS_FILE,
            accounts
          );

        if (!saved) {

          return res.status(500).send(

            "تعذر حفظ معلومات تسجيل الدخول."

          );

        }

        if (!account.accessKey) {

          return res.status(500).send(

            "الحساب موجود ولكن لا يوجد Access Key."

          );

        }

        return res.redirect(

          `${FRONTEND_URL}?accessKey=${encodeURIComponent(
            account.accessKey
          )}`

        );

      }

      // ==================================================
      // حساب Discord جديد
      // ==================================================

      const keyIndex =
        keys.findIndex(

          (item) =>

            item &&
            typeof item.key ===
              "string" &&
            item.used === false

        );

      // لا توجد مفاتيح
      if (keyIndex === -1) {

        return res.status(403).send(

          "تم تسجيل الدخول إلى Discord بنجاح، لكن لا توجد Access Keys متاحة حالياً. يجب على الإدارة إنشاء مفتاح جديد."

        );

      }

      const selectedKey =
        keys[keyIndex].key;

      // ==================================================
      // إنشاء Username
      // ==================================================

      const baseUsername =

        (

          discordUser.global_name ||
          discordUser.username ||
          `discord_${discordUser.id}`

        )

          .trim()

          .replace(
            /[^a-zA-Z0-9_-]/g,
            "_"
          )

          .slice(0, 20) ||

        `discord_${discordUser.id}`;

      let username =
        baseUsername;

      let counter = 1;

      while (

        accounts.some(

          (account) =>

            account &&
            typeof account.username ===
              "string" &&
            account.username
              .toLowerCase() ===
              username.toLowerCase()

        )

      ) {

        username =
          `${baseUsername}_${counter}`
            .slice(0, 24);

        counter++;

      }

      // ==================================================
      // كلمة مرور عشوائية للحساب
      // ==================================================

      const randomPassword =
        crypto
          .randomBytes(32)
          .toString("hex");

      const passwordHash =
        await bcrypt.hash(
          randomPassword,
          12
        );

      const now =
        new Date().toISOString();

      // ==================================================
      // إنشاء الحساب
      // ==================================================

      const newAccount = {

        username:
          username,

        password:
          passwordHash,

        accessKey:
          selectedKey,

        discordId:
          discordUser.id,

        discordUsername:
          discordUser.username ||
          null,

        discordGlobalName:
          discordUser.global_name ||
          null,

        discordAvatar:
          discordUser.avatar ||
          null,

        authProvider:
          "discord",

        createdAt:
          now,

        lastLoginAt:
          now

      };

      accounts.push(
        newAccount
      );

      // ==================================================
      // استعمال Access Key
      // ==================================================

      keys[keyIndex].used =
        true;

      keys[keyIndex].usedBy =
        username;

      keys[keyIndex].discordId =
        discordUser.id;

      keys[keyIndex].usedAt =
        now;

      // ==================================================
      // حفظ الحساب
      // ==================================================

      const accountsSaved =
        writeJSON(
          ACCOUNTS_FILE,
          accounts
        );

      if (!accountsSaved) {

        return res.status(500).send(

          "تعذر حفظ حساب Discord."

        );

      }

      // ==================================================
      // حفظ المفتاح
      // ==================================================

      const keysSaved =
        writeJSON(
          KEYS_FILE,
          keys
        );

      if (!keysSaved) {

        // Rollback
        accounts.pop();

        writeJSON(
          ACCOUNTS_FILE,
          accounts
        );

        return res.status(500).send(

          "تعذر حفظ Access Key."

        );

      }

      // ==================================================
      // نجاح
      // ==================================================

      return res.redirect(

        `${FRONTEND_URL}?accessKey=${encodeURIComponent(
          selectedKey
        )}`

      );

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
// إنشاء Access Key
// ==================================================

async function createAccessKey(
  req,
  res
) {

  try {

    const adminKey =
      process.env.ADMIN_KEY;

    if (!adminKey) {

      return res.status(500).json({

        success: false,

        message:
          "ADMIN_KEY is not configured on the server"

      });

    }

    const body =
      req.body || {};

    const providedAdminKey =

      typeof body.adminKey ===
      "string"

        ? body.adminKey.trim()

        : "";

    if (

      !providedAdminKey ||
      providedAdminKey !==
        adminKey

    ) {

      return res.status(401).json({

        success: false,

        message:
          "Unauthorized"

      });

    }

    const key =

      "N10-" +
      crypto
        .randomBytes(16)
        .toString("hex");

    const keys =
      readJSON(
        KEYS_FILE
      );

    keys.push({

      key:
        key,

      used:
        false,

      createdAt:
        new Date().toISOString()

    });

    const saved =
      writeJSON(
        KEYS_FILE,
        keys
      );

    if (!saved) {

      return res.status(500).json({

        success: false,

        message:
          "Failed to save access key"

      });

    }

    return res.status(201).json({

      success: true,

      accessKey:
        key

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

    const body =
      req.body || {};

    const username =

      typeof body.username ===
      "string"

        ? body.username.trim()

        : "";

    const password =

      typeof body.password ===
      "string"

        ? body.password

        : "";

    const accessKey =

      typeof body.accessKey ===
      "string"

        ? body.accessKey.trim()

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
          "اسم المستخدم يجب أن يكون بين 3 و 24 حرفاً"

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

    const accounts =
      readJSON(
        ACCOUNTS_FILE
      );

    const keys =
      readJSON(
        KEYS_FILE
      );

    const usernameExists =
      accounts.some(

        (account) =>

          account &&

          typeof account.username ===
            "string" &&

          account.username
            .toLowerCase() ===
            username.toLowerCase()

      );

    if (usernameExists) {

      return res.status(409).json({

        success: false,

        message:
          "اسم المستخدم موجود بالفعل"

      });

    }

    const keyIndex =
      keys.findIndex(

        (item) =>

          item &&
          item.key ===
            accessKey &&
          item.used === false

      );

    if (keyIndex === -1) {

      return res.status(403).json({

        success: false,

        message:
          "Access Key غير صالح أو تم استعماله من قبل"

      });

    }

    const passwordHash =
      await bcrypt.hash(
        password,
        12
      );

    const account = {

      username:
        username,

      password:
        passwordHash,

      accessKey:
        accessKey,

      authProvider:
        "password",

      createdAt:
        new Date().toISOString()

    };

    accounts.push(
      account
    );

    keys[keyIndex].used =
      true;

    keys[keyIndex].usedBy =
      username;

    keys[keyIndex].usedAt =
      new Date().toISOString();

    const accountsSaved =
      writeJSON(
        ACCOUNTS_FILE,
        accounts
      );

    if (!accountsSaved) {

      return res.status(500).json({

        success: false,

        message:
          "Failed to save account data"

      });

    }

    const keysSaved =
      writeJSON(
        KEYS_FILE,
        keys
      );

    if (!keysSaved) {

      accounts.pop();

      writeJSON(
        ACCOUNTS_FILE,
        accounts
      );

      return res.status(500).json({

        success: false,

        message:
          "Failed to save key data"

      });

    }

    return res.status(201).json({

      success: true,

      message:
        "Account created successfully",

      user: {

        username:
          username,

        accessKey:
          accessKey

      }

    });

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
// Login
// ==================================================

async function login(
  req,
  res
) {

  try {

    const body =
      req.body || {};

    const username =

      typeof body.username ===
      "string"

        ? body.username.trim()

        : "";

    const password =

      typeof body.password ===
      "string"

        ? body.password

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

    const accounts =
      readJSON(
        ACCOUNTS_FILE
      );

    const account =
      accounts.find(

        (item) =>

          item &&

          typeof item.username ===
            "string" &&

          item.username
            .toLowerCase() ===
            username.toLowerCase()

      );

    if (!account) {

      return res.status(401).json({

        success: false,

        message:
          "اسم المستخدم أو كلمة المرور غير صحيحة"

      });

    }

    // حساب Discord يدخل عبر Discord
    if (

      account.authProvider ===
        "discord" &&

      account.discordId

    ) {

      return res.status(403).json({

        success: false,

        message:
          "هذا الحساب مرتبط بـ Discord. استعمل تسجيل الدخول عبر Discord."

      });

    }

    if (!account.password) {

      return res.status(401).json({

        success: false,

        message:
          "اسم المستخدم أو كلمة المرور غير صحيحة"

      });

    }

    const passwordCorrect =
      await bcrypt.compare(

        password,

        account.password

      );

    if (!passwordCorrect) {

      return res.status(401).json({

        success: false,

        message:
          "اسم المستخدم أو كلمة المرور غير صحيحة"

      });

    }

    return res.json({

      success: true,

      message:
        "Login successful",

      user: {

        username:
          account.username,

        accessKey:
          account.accessKey ||
          null

      },

      accessKey:
        account.accessKey ||
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
// تشغيل السيرفر
// ==================================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `N10 Discord Backend running on port ${PORT}`
    );

    console.log(
      "Health: /health"
    );

    console.log(
      "Discord OAuth: /auth/discord"
    );

    console.log(
      "Discord Callback: /auth/discord/callback"
    );

  }
);
