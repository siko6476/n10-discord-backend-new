require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const path = require("path");

const app = express();

app.use(cors());
app.use(express.json());

// Serve public/index.html
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

const DISCORD_CLIENT_ID =
  process.env.DISCORD_CLIENT_ID;

const DISCORD_CLIENT_SECRET =
  process.env.DISCORD_CLIENT_SECRET;

const DISCORD_REDIRECT_URI =
  "https://n10-discord-backend-new.onrender.com/auth/discord/callback";

const SESSION_MS =
  30 * 24 * 60 * 60 * 1000;

/* =================================
   BASIC
================================= */

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

/* =================================
   DISCORD STATE
================================= */

const oauthStates = new Map();

function createState() {
  const state = crypto.randomBytes(32).toString("hex");

  oauthStates.set(state, Date.now());

  return state;
}

function verifyState(state) {
  if (!state) return false;

  const createdAt = oauthStates.get(state);

  if (!createdAt) {
    return false;
  }

  oauthStates.delete(state);

  // State valid for 10 minutes
  if (Date.now() - createdAt > 10 * 60 * 1000) {
    return false;
  }

  return true;
}

/* =================================
   HELPERS
================================= */

function randomToken(bytes = 32) {
  return crypto
    .randomBytes(bytes)
    .toString("hex");
}

function generateAccessKey() {
  return (
    "N10-" +
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase() +
    "-" +
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase()
  );
}

function cleanUsername(name) {
  return String(name || "")
    .replace(/[^a-zA-Z0-9_.-]/g, "_")
    .slice(0, 24) || "DiscordUser";
}

async function uniqueUsername(base) {
  const cleanBase = cleanUsername(base);

  let username = cleanBase;

  for (let i = 0; i < 100; i++) {
    const result = await pool.query(
      `
      SELECT id
      FROM accounts
      WHERE username = $1
      LIMIT 1
      `,
      [username]
    );

    if (result.rows.length === 0) {
      return username;
    }

    const suffix =
      "_" + Math.floor(Math.random() * 9999);

    username =
      cleanBase.slice(
        0,
        24 - suffix.length
      ) + suffix;
  }

  throw new Error(
    "Unable to generate username"
  );
}

/* =================================
   HOME
================================= */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* =================================
   DISCORD LOGIN
================================= */

app.get("/auth/discord", (req, res) => {
  try {
    if (
      !DISCORD_CLIENT_ID ||
      !DISCORD_CLIENT_SECRET
    ) {
      return res.status(500).json({
        ok: false,
        error:
          "Discord OAuth is not configured.",
      });
    }

    const state = createState();

    const params = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      response_type: "code",
      redirect_uri:
        DISCORD_REDIRECT_URI,
      scope: "identify",
      state,
    });

    const discordURL =
      "https://discord.com/oauth2/authorize?" +
      params.toString();

    res.redirect(discordURL);
  } catch (error) {
    console.error(
      "Discord start error:",
      error
    );

    res.status(500).send(
      "Unable to start Discord login."
    );
  }
});

/* =================================
   DISCORD CALLBACK
================================= */

app.get(
  "/auth/discord/callback",
  async (req, res) => {
    try {
      const code =
        typeof req.query.code === "string"
          ? req.query.code
          : "";

      const state =
        typeof req.query.state === "string"
          ? req.query.state
          : "";

      const discordError =
        typeof req.query.error === "string"
          ? req.query.error
          : "";

      if (discordError) {
        return res.status(400).send(`
          <h2>Discord Login Cancelled</h2>
          <p>You cancelled Discord authorization.</p>
          <a href="/">Back</a>
        `);
      }

      if (!verifyState(state)) {
        return res.status(400).send(`
          <h2>Invalid Login</h2>
          <p>The Discord login session expired.</p>
          <a href="/">Try Again</a>
        `);
      }

      if (!code) {
        return res.status(400).send(
          "Discord authorization code is missing."
        );
      }

      /* =========================
         GET DISCORD TOKEN
      ========================= */

      const tokenResponse =
        await fetch(
          "https://discord.com/api/v10/oauth2/token",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded",
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
                  DISCORD_REDIRECT_URI,
              }).toString(),
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

        return res.status(400).send(`
          <h2>Discord Login Failed</h2>
          <p>Could not obtain Discord authorization.</p>
        `);
      }

      /* =========================
         GET DISCORD USER
      ========================= */

      const userResponse =
        await fetch(
          "https://discord.com/api/v10/users/@me",
          {
            headers: {
              Authorization:
                `Bearer ${tokenData.access_token}`,
            },
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

        return res.status(400).send(`
          <h2>Discord Login Failed</h2>
          <p>Could not get your Discord account.</p>
        `);
      }

      const discordId =
        String(discordUser.id);

      const discordUsername =
        String(
          discordUser.username || ""
        );

      const discordGlobalName =
        String(
          discordUser.global_name || ""
        );

      const discordAvatar =
        discordUser.avatar
          ? `https://cdn.discordapp.com/avatars/${discordId}/${discordUser.avatar}.png`
          : "";

      console.log(
        "Discord login:",
        discordId,
        discordUsername
      );

      /* =========================
         FIND ACCOUNT
      ========================= */

      const accountResult =
        await pool.query(
          `
          SELECT
            id,
            username,
            discord_id,
            access_key
          FROM accounts
          WHERE discord_id = $1
          LIMIT 1
          `,
          [discordId]
        );

      let account;
      let accessKey;

      /* =========================
         EXISTING ACCOUNT
      ========================= */

      if (accountResult.rows.length > 0) {
        account =
          accountResult.rows[0];

        accessKey =
          account.access_key || null;

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
          await uniqueUsername(
            discordUsername
          );

        const randomPassword =
          randomToken(32);

        const passwordHash =
          await bcrypt.hash(
            randomPassword,
            12
          );

        accessKey =
          generateAccessKey();

        const insertResult =
          await pool.query(
            `
            INSERT INTO accounts
            (
              username,
              password,
              access_key,
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
              $7,
              'discord',
              NOW(),
              NOW()
            )
            RETURNING
              id,
              username,
              discord_id,
              access_key
            `,
            [
              username,
              passwordHash,
              accessKey,
              discordId,
              discordUsername,
              discordGlobalName,
              discordAvatar,
            ]
          );

        account =
          insertResult.rows[0];

        /* Create access key record */

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
      }

      /* =========================
         SESSION
      ========================= */

      const sessionToken =
        randomToken(48);

      const expiresAt =
        new Date(
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
         SUCCESS
      ========================= */

      res.send(`
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>

<title>N10 Login</title>

<style>

body {
  margin: 0;
  min-height: 100vh;
  background: #111;
  color: white;
  font-family: Arial, sans-serif;

  display: flex;
  align-items: center;
  justify-content: center;
}

.box {
  width: 90%;
  max-width: 420px;

  background: #1d1d1d;

  padding: 30px;

  border-radius: 20px;

  text-align: center;
}

h1 {
  color: #5865F2;
}

.success {
  color: #57F287;
}

.key {
  margin-top: 20px;

  padding: 15px;

  background: #000;

  border-radius: 10px;

  word-break: break-all;

  font-size: 18px;
}

button {
  margin-top: 20px;

  padding: 12px 25px;

  border: none;

  border-radius: 8px;

  background: #5865F2;

  color: white;

  font-weight: bold;
}

</style>

</head>

<body>

<div class="box">

<h1>N10 SERVER</h1>

<h2 class="success">
Discord Login Successful
</h2>

<p>
Welcome
<strong>${discordUsername}</strong>
</p>

<p>
Game Account:
<strong>${account.username}</strong>
</p>

<p>
Your Access Key:
</p>

<div class="key">
${accessKey || "Already assigned"}
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

      res.status(500).send(`
        <h2>Server Error</h2>
        <p>Something went wrong.</p>
      `);
    }
  }
);

/* =================================
   START SERVER
================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `N10 Backend running on port ${PORT}`
    );
  }
);
