require("dotenv").config();

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();

const PORT = process.env.PORT || 3000;

// =========================
// ملفات البيانات
// =========================

const ACCOUNTS_FILE = path.join(__dirname, "accounts.json");
const KEYS_FILE = path.join(__dirname, "keys.json");
const INDEX_FILE = path.join(__dirname, "index.html");

// =========================
// Middleware
// =========================

app.use(express.json({ limit: "1mb" }));

// =========================
// CORS
// =========================

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
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

// =========================
// ملفات JSON
// =========================

function ensureFile(file) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, "[]", "utf8");
      console.log(`Created: ${path.basename(file)}`);
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

// =========================
// قراءة JSON
// =========================

function readJSON(file) {
  try {
    if (!fs.existsSync(file)) {
      return [];
    }

    const content = fs
      .readFileSync(file, "utf8")
      .trim();

    if (!content) {
      return [];
    }

    const data = JSON.parse(content);

    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error(
      `Error reading ${path.basename(file)}:`,
      error
    );

    return [];
  }
}

// =========================
// كتابة JSON
// =========================

function writeJSON(file, data) {
  try {
    fs.writeFileSync(
      file,
      JSON.stringify(data, null, 2),
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

// =========================
// الصفحة الرئيسية
// =========================

app.get("/", (req, res) => {
  if (!fs.existsSync(INDEX_FILE)) {
    return res.status(500).json({
      success: false,
      message: "index.html is missing"
    });
  }

  res.sendFile(INDEX_FILE);
});

// =========================
// Health Check
// =========================

app.get("/health", (req, res) => {
  res.json({
    success: true,
    ok: true,
    status: "online",
    service: "N10 Discord Backend",
    version: "1.0.0"
  });
});

// =========================
// إنشاء Access Key
// =========================

async function createAccessKey(req, res) {
  try {
    const adminKey = process.env.ADMIN_KEY;

    if (!adminKey) {
      return res.status(500).json({
        success: false,
        message:
          "ADMIN_KEY is not configured on the server"
      });
    }

    const body = req.body || {};

    const providedAdminKey =
      typeof body.adminKey === "string"
        ? body.adminKey.trim()
        : "";

    if (
      !providedAdminKey ||
      providedAdminKey !== adminKey
    ) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized"
      });
    }

    const key =
      "N10-" +
      crypto.randomBytes(16).toString("hex");

    const keys = readJSON(KEYS_FILE);

    keys.push({
      key: key,
      used: false,
      createdAt: new Date().toISOString()
    });

    const saved = writeJSON(
      KEYS_FILE,
      keys
    );

    if (!saved) {
      return res.status(500).json({
        success: false,
        message: "Failed to save access key"
      });
    }

    return res.status(201).json({
      success: true,
      accessKey: key
    });
  } catch (error) {
    console.error(
      "Create Key Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Internal server error"
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

// =========================
// Register
// =========================

async function register(req, res) {
  try {
    const body = req.body || {};

    const username =
      typeof body.username === "string"
        ? body.username.trim()
        : "";

    const password =
      typeof body.password === "string"
        ? body.password
        : "";

    const accessKey =
      typeof body.accessKey === "string"
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

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message:
          "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
      });
    }

    const accounts =
      readJSON(ACCOUNTS_FILE);

    const keys =
      readJSON(KEYS_FILE);

    // =========================
    // التحقق من Username
    // =========================

    const usernameExists =
      accounts.some(
        (account) =>
          account &&
          typeof account.username === "string" &&
          account.username.toLowerCase() ===
            username.toLowerCase()
      );

    if (usernameExists) {
      return res.status(409).json({
        success: false,
        message:
          "اسم المستخدم موجود بالفعل"
      });
    }

    // =========================
    // التحقق من Access Key
    // =========================

    const keyIndex =
      keys.findIndex(
        (item) =>
          item &&
          item.key === accessKey &&
          item.used === false
      );

    if (keyIndex === -1) {
      return res.status(403).json({
        success: false,
        message:
          "Access Key غير صالح أو تم استعماله من قبل"
      });
    }

    // =========================
    // تشفير كلمة المرور
    // =========================

    const passwordHash =
      await bcrypt.hash(
        password,
        12
      );

    // =========================
    // إنشاء الحساب
    // =========================

    const account = {
      username: username,
      password: passwordHash,
      accessKey: accessKey,
      createdAt:
        new Date().toISOString()
    };

    accounts.push(account);

    // =========================
    // استعمال المفتاح
    // =========================

    keys[keyIndex].used = true;
    keys[keyIndex].usedBy = username;
    keys[keyIndex].usedAt =
      new Date().toISOString();

    // =========================
    // حفظ الحسابات
    // =========================

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

    // =========================
    // حفظ المفاتيح
    // =========================

    const keysSaved =
      writeJSON(
        KEYS_FILE,
        keys
      );

    if (!keysSaved) {
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
        username: username,
        accessKey: accessKey
      }
    });
  } catch (error) {
    console.error(
      "Register Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Internal server error"
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

// =========================
// Login
// =========================

async function login(req, res) {
  try {
    const body = req.body || {};

    const username =
      typeof body.username === "string"
        ? body.username.trim()
        : "";

    const password =
      typeof body.password === "string"
        ? body.password
        : "";

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message:
          "Username and password are required"
      });
    }

    const accounts =
      readJSON(ACCOUNTS_FILE);

    const account =
      accounts.find(
        (item) =>
          item &&
          typeof item.username === "string" &&
          item.username.toLowerCase() ===
            username.toLowerCase()
      );

    if (!account) {
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
      message: "Login successful",
      user: {
        username: account.username,
        accessKey:
          account.accessKey || null
      },
      accessKey:
        account.accessKey || null
    });
  } catch (error) {
    console.error(
      "Login Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Internal server error"
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

// =========================
// 404
// =========================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message:
      `Route not found: ${req.method} ${req.originalUrl}`
  });
});

// =========================
// Error Handler
// =========================

app.use(
  (err, req, res, next) => {
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

// =========================
// تشغيل السيرفر
// =========================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `N10 Discord Backend running on port ${PORT}`
    );

    console.log(
      `Health: /health`
    );
  }
);
