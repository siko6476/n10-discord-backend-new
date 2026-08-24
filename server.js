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

const FRONTEND_URL = (
  process.env.FRONTEND_URL ||
  "https://siko6476.github.io/N10-SERVER-MENA"
).replace(/\/+$/, "");

const FRONTEND_ORIGIN = (
  process.env.FRONTEND_ORIGIN ||
  "https://siko6476.github.io"
).replace(/\/+$/, "");

const SESSION_MS =
  30 * 24 * 60 * 60 * 1000;


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


function generateSessionToken() {
  return crypto
    .randomBytes(48)
    .toString("hex");
}


function generateAccessKey() {
  return (
    "N10-" +
    crypto
      .randomBytes(18)
      .toString("hex")
      .toUpperCase()
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
        24 - suffix.length
      ) + suffix;
  }

  throw new Error(
    "Unable to generate unique username"
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
    age <= 10 * 60 * 1000
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
    version: "1.0.0",
    status: "online",
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

      return res.json({
        success: true,
        status: "online",
        database: "connected"
      });

    } catch (error) {

      console.error(
        "Health Error:",
        error
      );

      return res.status(500).json({
        success: false,
        status: "online",
        database: "offline"
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
          "Discord OAuth is not configured."
        );
      }

      const state =
        createOAuthState();

      /*
       * IMPORTANT:
       * The redirect URI here MUST be exactly
       * the same as the one registered in
       * Discord Developer Portal.
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

      noCache(res);

      return res.redirect(
        "https://discord.com/oauth2/authorize?" +
        params.toString()
      );

    } catch (error) {

      console.error(
        "Discord Start Error:",
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

    try {

      noCache(res);

      /* -----------------------------------------
         Get OAuth parameters
      ----------------------------------------- */

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


      /* -----------------------------------------
         User cancelled Discord login
      ----------------------------------------- */

      if (discordError) {

        return res.redirect(
          frontendRedirect({
            discordError:
              "تم إلغاء تسجيل الدخول عبر Discord."
          })
        );
      }


      /* -----------------------------------------
         Verify state
      ----------------------------------------- */

      if (
        !verifyOAuthState(state)
      ) {

        return res.redirect(
          frontendRedirect({
            discordError:
              "جلسة Discord غير صالحة أو انتهت."
          })
        );
      }


      /* -----------------------------------------
         Check code
      ----------------------------------------- */

      if (!code) {

        return res.redirect(
          frontendRedirect({
            discordError:
              "لم يتم استلام كود Discord."
          })
        );
      }


      /* =================================================
         EXCHANGE DISCORD CODE
      ================================================= */

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
              "فشل تسجيل الدخول عبر Discord."
          })
        );
      }


      /* =================================================
         GET DISCORD USER
      ================================================= */

      const userResponse =
        await fetch(
          "https://discord.com/api/v10/users/@me",
          {
            method: "GET",

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
              "تعذر الحصول على بيانات Discord."
          })
        );
      }


      /* =================================================
         DISCORD DATA
      ================================================= */

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
        "Discord OAuth SUCCESS:",
        discordUsername,
        discordId
      );


      /* =================================================
         FIND ACCOUNT
      ================================================= */

      const accountResult =
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


      let account;
      let accessKey;


      /* =================================================
         EXISTING ACCOUNT
      ================================================= */

      if (
        accountResult.rows.length > 0
      ) {

        account =
          accountResult.rows[0];

        accessKey =
          account.access_key || null;


        /* -----------------------------------------
           Create missing access key
        ----------------------------------------- */

        if (!accessKey) {

          accessKey =
            generateAccessKey();

          await pool.query(
            `
            UPDATE accounts
            SET
              access_key = $1
            WHERE id = $2
            `,
            [
              accessKey,
              account.id
            ]
          );


          /* Save key in access_keys */

          await pool.query(
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


        /* -----------------------------------------
           Update Discord information
        ----------------------------------------- */

        await pool.query(
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

      }


      /* =================================================
         NEW ACCOUNT
      ================================================= */

      else {

        const username =
          await uniqueUsername(
            discordUsername
          );


        /* Random password */

        const randomPassword =
          crypto
            .randomBytes(32)
            .toString("hex");


        const passwordHash =
          await bcrypt.hash(
            randomPassword,
            12
          );


        /* New access key */

        accessKey =
          generateAccessKey();


        /* -----------------------------------------
           Create account
        ----------------------------------------- */

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


        /* -----------------------------------------
           Save access key
        ----------------------------------------- */

        await pool.query(
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


      /* =================================================
         CREATE SESSION
      ================================================= */

      const sessionToken =
        generateSessionToken();


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
          expiresAt
        ]
      );


      /* =================================================
         SUCCESS
      ================================================= */

      console.log(
        "N10 LOGIN SUCCESS:",
        account.username
      );


      return res.redirect(
        frontendRedirect({
          login: "success",
          username:
            account.username
        })
      );

    } catch (error) {

      console.error(
        "Discord Callback Error:",
        error
      );

      return res.redirect(
        frontendRedirect({
          discordError:
            "حدث خطأ في السيرفر أثناء تسجيل الدخول."
        })
      );
    }
  }
);


/* =========================================================
   404
========================================================= */

app.use(
  (req, res) => {

    noCache(res);

    return res.status(404).json({
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

    return res.status(500).json({
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
      `N10 Backend running on port ${PORT}`
    );

    console.log(
      `Frontend: ${FRONTEND_URL}`
    );

    console.log(
      `Discord Redirect: ${DISCORD_REDIRECT_URI}`
    );
  }
);
