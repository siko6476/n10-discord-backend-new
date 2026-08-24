"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 3000);

const FRONTEND_URL = (
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io/N10-SERVER-MENA"
).replace(/\/+$/, "");

const FRONTEND_ORIGIN = (
  process.env.FRONTEND_ORIGIN ||
  "https://siko6476.github.io"
).replace(/\/+$/, "");

const DATABASE_URL = process.env.DATABASE_URL || "";

const DISCORD_CLIENT_ID =
  process.env.DISCORD_CLIENT_ID || "";

const DISCORD_CLIENT_SECRET =
  process.env.DISCORD_CLIENT_SECRET || "";

const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI ||
  "https://n10-discord-backend-new.onrender.com/auth/discord/callback";

const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET || "";

const SESSION_MS =
  30 * 24 * 60 * 60 * 1000;

const OAUTH_STATE_MS =
  10 * 60 * 1000;


/* =========================================================
   ENV CHECK
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

if (!OAUTH_STATE_SECRET) {
  missing.push("OAUTH_STATE_SECRET");
}

if (missing.length > 0) {
  console.error(
    "Missing Environment Variables:",
    missing.join(", ")
  );
}


/* =========================================================
   POSTGRESQL
========================================================= */

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
    "PostgreSQL Pool Error:",
    error
  );
});


/* =========================================================
   MIDDLEWARE
========================================================= */

app.disable("x-powered-by");

app.set("trust proxy", 1);

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
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
    credentials: false
  })
);

app.use(express.json());

app.use(
  express.urlencoded({
    extended: true
  })
);


/* =========================================================
   HELPERS
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

  res.setHeader(
    "Surrogate-Control",
    "no-store"
  );
}


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


function randomHex(bytes = 32) {
  return crypto
    .randomBytes(bytes)
    .toString("hex");
}


function generateSessionToken() {
  return randomHex(48);
}


function generateAccessKey() {
  return (
    "N10-" +
    randomHex(18).toUpperCase()
  );
}


function cleanUsername(name) {
  return String(name || "")
    .replace(
      /[^a-zA-Z0-9_.-]/g,
      "_"
    )
    .slice(0, 24) || "DiscordUser";
}


/* =========================================================
   UNIQUE USERNAME
========================================================= */

async function uniqueUsername(base) {

  const cleanBase =
    cleanUsername(base);

  let username = cleanBase;

  for (let i = 0; i < 100; i++) {

    const result =
      await pool.query(
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
      "_" +
      Math.floor(
        Math.random() * 9999
      );

    username =
      cleanBase.slice(
        0,
        Math.max(
          1,
          24 - suffix.length
        )
      ) + suffix;
  }

  throw new Error(
    "Could not generate unique username"
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
      "OAUTH_STATE_SECRET is missing"
    );
  }

  const timestamp =
    Date.now().toString();

  const random =
    randomHex(32);

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
    !/^[a-f0-9]{64}$/.test(
      random
    ) ||
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

  if (a.length !== b.length) {
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

  if (!Number.isFinite(createdAt)) {
    return false;
  }

  const age =
    Date.now() - createdAt;

  return (
    age >= 0 &&
    age <= OAUTH_STATE_MS
  );
}


/* =========================================================
   COOKIE HELPERS
========================================================= */

function parseCookies(req) {

  const header =
    req.headers.cookie || "";

  const cookies = {};

  for (
    const part
    of header.split(";")
  ) {

    const index =
      part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      part
        .slice(0, index)
        .trim();

    const value =
      part
        .slice(index + 1)
        .trim();

    cookies[key] =
      decodeURIComponent(value);
  }

  return cookies;
}


function setOAuthCookie(
  res,
  state
) {

  const cookie =
    [
      `n10_oauth_state=${encodeURIComponent(state)}`,
      "Path=/auth/discord",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Max-Age=600"
    ].join("; ");

  res.setHeader(
    "Set-Cookie",
    cookie
  );
}


function clearOAuthCookie(res) {

  const cookie =
    [
      "n10_oauth_state=",
      "Path=/auth/discord",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Max-Age=0"
    ].join("; ");

  res.setHeader(
    "Set-Cookie",
    cookie
  );
}


/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {

  noCache(res);

  res.json({
    success: true,
    name: "N10 SERVER MENA",
    status: "online",
    version: "1.0.0",
    discord: true,
    database: "PostgreSQL"
  });
});


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

      res.json({
        success: true,
        status: "online",
        database: "connected"
      });

    } catch (error) {

      console.error(
        "Health Error:",
        error
      );

      res.status(500).json({
        success: false,
        status: "online",
        database: "disconnected"
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

      noCache(res);

      if (
        !DISCORD_CLIENT_ID ||
        !DISCORD_CLIENT_SECRET ||
        !OAUTH_STATE_SECRET
      ) {

        return sendError(
          res,
          500,
          "Discord OAuth is not configured."
        );
      }

      const state =
        createOAuthState();

      /*
       * Save state in secure cookie
       */

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

      const discordUrl =
        "https://discord.com/oauth2/authorize?" +
        params.toString();

      return res.redirect(
        discordUrl
      );

    } catch (error) {

      console.error(
        "Discord Login Start Error:",
        error
      );

      return sendError(
        res,
        500,
        "Unable to start Discord login."
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

    const client =
      await pool.connect();

    try {

      noCache(res);

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

      const cookies =
        parseCookies(req);

      const savedState =
        cookies.n10_oauth_state || "";


      /* =====================================
         CANCELLED
      ===================================== */

      if (discordError) {

        clearOAuthCookie(res);

        return res.redirect(
          frontendRedirect({
            discordError:
              "تم إلغاء تسجيل الدخول عبر Discord."
          })
        );
      }


      /* =====================================
         CHECK STATE
      ===================================== */

      if (
        !state ||
        !savedState ||
        state !== savedState ||
        !verifyOAuthState(state)
      ) {

        clearOAuthCookie(res);

        return res.redirect(
          frontendRedirect({
            discordError:
              "جلسة Discord غير صالحة أو انتهت."
          })
        );
      }

      clearOAuthCookie(res);


      /* =====================================
         CHECK CODE
      ===================================== */

      if (!code) {

        return res.redirect(
          frontendRedirect({
            discordError:
              "لم يتم استلام كود Discord."
          })
        );
      }


      /* =====================================
         EXCHANGE CODE
      ===================================== */

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
          frontendRedirect({
            discordError:
              "فشل تسجيل الدخول إلى Discord."
          })
        );
      }


      /* =====================================
         GET DISCORD USER
      ===================================== */

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
          "Discord user error:",
          discordUser
        );

        return res.redirect(
          frontendRedirect({
            discordError:
              "تعذر الحصول على حساب Discord."
          })
        );
      }


      /* =====================================
         DISCORD DATA
      ===================================== */

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

      const discordAvatar =
        discordUser.avatar
          ? `https://cdn.discordapp.com/avatars/${discordId}/${discordUser.avatar}.png`
          : "";


      console.log(
        "Discord OAuth:",
        discordUsername,
        discordId
      );


      /* =====================================
         START DATABASE TRANSACTION
      ===================================== */

      await client.query(
        "BEGIN"
      );


      /* =====================================
         FIND ACCOUNT
      ===================================== */

      const accountResult =
        await client.query(
          `
          SELECT
            id,
            username,
            password,
            access_key,
            discord_id
          FROM accounts
          WHERE discord_id = $1
          LIMIT 1
          FOR UPDATE
          `,
          [discordId]
        );


      let account;
      let accessKey;


      /* =====================================
         EXISTING ACCOUNT
      ===================================== */

      if (
        accountResult.rows.length > 0
      ) {

        account =
          accountResult.rows[0];

        accessKey =
          account.access_key || null;


        /* Update Discord information */

        await client.query(
          `
          UPDATE accounts
          SET
            discord_username = $1,
            discord_global_name = $2,
            discord_avatar = $3,
            auth_provider = 'discord',
            last_login_at = NOW()
          WHERE id = $4
          `,
          [
            discordUsername,
            discordGlobalName,
            discordAvatar,
            account.id
          ]
        );


        /* =================================
           CREATE ACCESS KEY IF MISSING
        ================================= */

        if (!accessKey) {

          accessKey =
            generateAccessKey();

          await client.query(
            `
            UPDATE accounts
            SET access_key = $1
            WHERE id = $2
            `,
            [
              accessKey,
              account.id
            ]
          );
        }


        /* =================================
           MAKE SURE ACCESS KEY EXISTS
           IN access_keys
        ================================= */

        const keyResult =
          await client.query(
            `
            SELECT id
            FROM access_keys
            WHERE key = $1
            LIMIT 1
            `,
            [accessKey]
          );

        if (
          keyResult.rows.length === 0
        ) {

          await client.query(
            `
            INSERT INTO access_keys
            (
              key,
              used,
              used_by,
              account_id,
              discord_id,
              created_at
            )
            VALUES
            (
              $1,
              FALSE,
              NULL,
              $2,
              $3,
              NOW()
            )
            `,
            [
              accessKey,
              account.id,
              discordId
            ]
          );
        }
      }


      /* =====================================
         NEW ACCOUNT
      ===================================== */

      else {

        const username =
          await uniqueUsername(
            discordUsername
          );

        const randomPassword =
          randomHex(32);

        const passwordHash =
          await bcrypt.hash(
            randomPassword,
            12
          );

        accessKey =
          generateAccessKey();


        /* =================================
           CREATE ACCOUNT
        ================================= */

        const insertResult =
          await client.query(
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
              access_key,
              discord_id
            `,
            [
              username,
              passwordHash,
              accessKey,
              discordId,
              discordUsername,
              discordGlobalName,
              discordAvatar
            ]
          );

        account =
          insertResult.rows[0];


        /* =================================
           CREATE ACCESS KEY
        ================================= */

        await client.query(
          `
          INSERT INTO access_keys
          (
            key,
            used,
            used_by,
            account_id,
            discord_id,
            created_at
          )
          VALUES
          (
            $1,
            FALSE,
            NULL,
            $2,
            $3,
            NOW()
          )
          `,
          [
            accessKey,
            account.id,
            discordId
          ]
        );
      }


      /* =====================================
         CREATE SESSION
      ===================================== */

      const sessionToken =
        generateSessionToken();

      const expiresAt =
        new Date(
          Date.now() + SESSION_MS
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


      /* =====================================
         COMMIT
      ===================================== */

      await client.query(
        "COMMIT"
      );


      console.log(
        "LOGIN SUCCESS:",
        account.username
      );


      /* =====================================
         SUCCESS
      ===================================== */

      return res.redirect(
        frontendRedirect({
          login: "success",
          username:
            account.username
        })
      );

    } catch (error) {

      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) {}

      console.error(
        "Discord callback error:",
        error
      );

      clearOAuthCookie(res);

      return res.redirect(
        frontendRedirect({
          discordError:
            "حدث خطأ في السيرفر أثناء تسجيل الدخول."
        })
      );

    } finally {

      client.release();
    }
  }
);


/* =========================================================
   404
========================================================= */

app.use(
  (req, res) => {

    noCache(res);

    res.status(404).json({
      success: false,
      message: "Route not found"
    });
  }
);


/* =========================================================
   GLOBAL ERROR
========================================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "Global Error:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "======================================"
    );

    console.log(
      `N10 SERVER MENA running on port ${PORT}`
    );

    console.log(
      `Frontend: ${FRONTEND_URL}`
    );

    console.log(
      `Discord Redirect: ${DISCORD_REDIRECT_URI}`
    );

    console.log(
      "PostgreSQL: configured"
    );

    console.log(
      "Discord OAuth: configured"
    );

    console.log(
      "======================================"
    );
  }
);
