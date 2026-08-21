const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const axios = require("axios");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// تخزين مؤقت للمستخدمين والمفاتيح
// لاحقًا نربطهم بقاعدة بيانات باش ما يضيعوش عند إعادة تشغيل السيرفر
const users = [];
const accessKeys = new Map();

// الصفحة الرئيسية
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "N10 Discord Backend is running!",
    version: "1.0.0"
  });
});

// فحص حالة السيرفر
app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    users: users.length,
    time: new Date().toISOString()
  });
});

// إنشاء Access Key
app.post("/api/admin/create-key", (req, res) => {
  const { adminKey, accessKey } = req.body;

  if (!process.env.ADMIN_KEY) {
    return res.status(500).json({
      success: false,
      message: "ADMIN_KEY is not configured"
    });
  }

  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({
      success: false,
      message: "Invalid admin key"
    });
  }

  if (!accessKey || accessKey.length < 6) {
    return res.status(400).json({
      success: false,
      message: "Access key must contain at least 6 characters"
    });
  }

  if (accessKeys.has(accessKey)) {
    return res.status(409).json({
      success: false,
      message: "Access key already exists"
    });
  }

  accessKeys.set(accessKey, {
    used: false,
    createdAt: new Date().toISOString()
  });

  res.json({
    success: true,
    message: "Access key created",
    accessKey
  });
});

// تسجيل مستخدم جديد
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, confirmPassword, accessKey } = req.body;

    if (!username || !password || !confirmPassword || !accessKey) {
      return res.status(400).json({
        success: false,
        message: "All fields are required"
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Passwords do not match"
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        success: false,
        message: "Username must contain at least 3 characters"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 6 characters"
      });
    }

    const keyInfo = accessKeys.get(accessKey);

    if (!keyInfo) {
      return res.status(403).json({
        success: false,
        message: "Invalid access key"
      });
    }

    if (keyInfo.used) {
      return res.status(403).json({
        success: false,
        message: "This access key has already been used"
      });
    }

    const existingUser = users.find(
      user => user.username.toLowerCase() === username.toLowerCase()
    );

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Username already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    users.push({
      id: Date.now().toString(),
      username,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    });

    // جعل المفتاح مستعمل
    keyInfo.used = true;
    keyInfo.usedAt = new Date().toISOString();

    res.status(201).json({
      success: true,
      message: "Account created successfully"
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

// تسجيل الدخول
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    const user = users.find(
      u => u.username.toLowerCase() === username.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    res.json({
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

// بدء Discord OAuth
app.get("/auth/discord", (req, res) => {
  if (!process.env.DISCORD_CLIENT_ID) {
    return res.status(500).send("Discord Client ID is not configured");
  }

  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    redirect_uri: process.env.DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify email"
  });

  res.redirect(
    `https://discord.com/oauth2/authorize?${params.toString()}`
  );
});

// Discord OAuth callback
app.get("/auth/discord/callback", async (req, res) => {
  try {
    const { code } = req.query;

    if (!code) {
      return res.status(400).json({
        success: false,
        message: "Authorization code is missing"
      });
    }

    res.json({
      success: true,
      message: "Discord callback received",
      code
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Discord authentication failed"
    });
  }
});

// تشغيل السيرفر
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
