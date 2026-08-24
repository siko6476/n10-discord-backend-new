require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
});

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;

const DISCORD_REDIRECT_URI =
  "https://n10-discord-backend-new.onrender.com/auth/discord/callback";

const SESSION_MS = 30 * 24 * 60 * 60 * 1000;

/* =========================
   HELPERS
========================= */

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function generateAccessKey() {
  return (
    "N10-" +
    crypto.randomBytes(4).toString("hex").toUpperCase() +
    "-" +
    crypto.randomBytes(4).toString("hex").toUpperCase()
  );
}

function cleanUsername(name) {
  return String(name || "")
    .replace(/[^a-zA-Z0-9_.-]/g, "_")
    .slice(0, 24) || "DiscordUser";
}

async function uniqueUsername(base) {
  let username = cleanUsername(base);

  for (let i = 0; i < 100; i++) {
    const result = await pool.query(
      "SELECT id FROM accounts WHERE username = $1 LIMIT 1",
      [username]
    );

    if (result.rows.length === 0) {
      return username;
    }

    const suffix = "_" + Math.floor(Math.random() * 9999);

    username =
      cleanUsername(base).slice(0, 24 - suffix.length) + suffix;
  }

  throw new Error("Unable to generate username");
}

/* =========================
   STATUS
========================= */

app.get("/", (req, res) => {
  res.json({
    ok: true,
    name: "N10 Discord Backend",
    version: "1.0.0",
    discord: true,
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "online",
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false,
      database: "offline",
    });
  }
});

/* =========================
   DISCORD LOGIN
========================= */

app.get("/auth/discord", (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
    return res.status(500).json({
      ok: false,
      error: "Discord OAuth is not configured.",
    });
  }

  const state = randomToken(24);

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: "identify",
    state,
  });

  res.cookie?.("oauth_state", state);

  res.redirect(
    "https://discord.com/oauth2/authorize?" +
    params.toString()
  );
});

/* =========================
   DISCORD CALLBACK
========================= */

app.get("/auth/discord/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");

    if (!code) {
      return res.status(400).send("Discord login cancelled.");
    }

    /* Get Discord token */

    const tokenResponse = await fetch(
      "https://discord.com/api/v10/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          client_id: DISCORD_CLIENT_ID,
          client_secret: DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: DISCORD_REDIRECT_URI,
        }).toString(),
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error("Discord token error:", tokenData);

      return res.status(400).send(
        "Discord authentication failed."
      );
    }

    /* Get Discord user */

    const userResponse = await fetch(
      "https://discord.com/api/v10/users/@me",
      {
        headers: {
          Authorization:
            `Bearer ${tokenData.access_token}`,
        },
      }
    );

    const discordUser = await userResponse.json();

    if (!userResponse.ok || !discordUser.id) {
      console.error("Discord user error:", discordUser);

      return res.status(400).send(
        "Could not get Discord account."
      );
    }

    const discordId = String(discordUser.id);

    const discordUsername =
      String(discordUser.username || "");

    const discordGlobalName =
      String(discordUser.global_name || "");

    const discordAvatar = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordId}/${discordUser.avatar}.png`
      : "";

    /* =========================
       FIND ACCOUNT
    ========================= */

    let accountResult = await pool.query(
      `
      SELECT
        id,
        username,
        discord_id
      FROM accounts
      WHERE discord_id = $1
      LIMIT 1
      `,
      [discordId]
    );

    let account;

    /* =========================
       EXISTING ACCOUNT
    ========================= */

    if (accountResult.rows.length > 0) {
      account = accountResult.rows[0];

      await pool.query(
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
          discordUsername,
          discordGlobalName,
          discordAvatar,
          account.id,
        ]
      );
    }

    /* =========================
       NEW ACCOUNT
    ========================= */

    else {
      const username =
        await uniqueUsername(discordUsername);

      /*
       * Random password hash.
       * User does NOT need to know this password
       * because authentication is through Discord.
       */

      const randomPassword = randomToken(32);

      const passwordHash =
        await bcrypt.hash(randomPassword, 12);

      const insertResult = await pool.query(
        `
        INSERT INTO accounts
        (
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
        VALUES
        (
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
        RETURNING id, username, discord_id
        `,
        [
          username,
          passwordHash,
          discordId,
          discordUsername,
          discordGlobalName,
          discordAvatar,
        ]
      );

      account = insertResult.rows[0];
    }

    /* =========================
       SESSION
    ========================= */

    const sessionToken = randomToken(48);

    const expiresAt = new Date(
      Date.now() + SESSION_MS
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
        expiresAt,
      ]
    );

    /* =========================
       ACCESS KEY
    ========================= */

    const accessKey = generateAccessKey();

    await pool.query(
      `
      INSERT INTO access_keys
      (
        key,
        used,
        account_id,
        discord_id,
        created_at
      )
      VALUES
      (
        $1,
        false,
        $2,
        $3,
        NOW()
      )
      `,
      [
        accessKey,
        account.id,
        discordId,
      ]
    );

    /* =========================
       SUCCESS
    ========================= */

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">
        <title>N10 Login</title>

        <style>
          body {
            background: #111;
            color: white;
            font-family: Arial;
            text-align: center;
            padding: 40px 20px;
          }

          .box {
            max-width: 420px;
            margin: auto;
            background: #1d1d1d;
            padding: 30px;
            border-radius: 18px;
          }

          h1 {
            color: #5865F2;
          }

          .key {
            background: #000;
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            word-break: break-all;
            font-size: 18px;
          }

          .success {
            color: #57F287;
          }
        </style>
      </head>

      <body>
        <div class="box">

          <h1>N10 LOGIN</h1>

          <h2 class="success">
            Discord Login Successful
          </h2>

          <p>
            Welcome ${discordUsername}
          </p>

          <p>
            Game Account:
            <b>${account.username}</b>
          </p>

          <p>
            Your Access Key:
          </p>

          <div class="key">
            ${accessKey}
          </div>

        </div>
      </body>
      </html>
    `);

  } catch (error) {
    console.error(
      "Discord callback error:",
      error
    );

    res.status(500).send(
      "Internal server error."
    );
  }
});

/* =========================
   START
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `N10 Backend running on port ${PORT}`
    );
  }
);
