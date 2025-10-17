import express from "express";
import session from "express-session";
import path from "path";
import dotenv from "dotenv";
import axios from "axios";
import { fileURLToPath } from "url";
import crypto from "crypto";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ESM-compatible __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Views
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use("/static", express.static(path.join(__dirname, "public")));

// Sessions (for demo only: MemoryStore; consider Redis in production)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret_change_me_",
    resave: false,
    saveUninitialized: false,
    cookie: { sameSite: "lax" },
  })
);

// Constants
const ATLASSIAN_AUTH_SERVER = "https://auth.atlassian.com";
const ATLASSIAN_API = "https://api.atlassian.com";
const SCOPES = [
  "read:me",
  "write:jira-work",
  "read:jira-user",
  "read:jira-work",
];

// PKCE helpers
function base64Url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function generateCodeVerifier() {
  return base64Url(crypto.randomBytes(32));
}

function generateCodeChallenge(codeVerifier) {
  const hash = crypto.createHash("sha256").update(codeVerifier).digest();
  return base64Url(hash);
}

function ensureAuth(req, res, next) {
  if (!req.session.tokens) {
    return res.redirect("/");
  }
  next();
}

// Routes
app.get("/", (req, res) => {
  const isConnected = Boolean(req.session.tokens);
  res.render("index", { isConnected });
});

app.get("/connect", async (req, res, next) => {
  try {
    const state = base64Url(crypto.randomBytes(16));
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    req.session.codeVerifier = codeVerifier;
    req.session.oauthState = state;
    const params = new URLSearchParams({
      audience: "api.atlassian.com",
      client_id: process.env.ATLASSIAN_CLIENT_ID,
      scope: SCOPES.join(" "),
      redirect_uri: process.env.ATLASSIAN_REDIRECT_URI,
      response_type: "code",
      prompt: "consent",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    res.redirect(`${ATLASSIAN_AUTH_SERVER}/authorize?${params.toString()}`);
  } catch (err) {
    next(err);
  }
});

app.get("/callback", async (req, res, next) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || state !== req.session.oauthState) {
      throw new Error("Invalid OAuth state or missing code");
    }
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: process.env.ATLASSIAN_CLIENT_ID,
      client_secret: process.env.ATLASSIAN_CLIENT_SECRET,
      code,
      redirect_uri: process.env.ATLASSIAN_REDIRECT_URI,
      code_verifier: req.session.codeVerifier,
    });
    const { data } = await axios.post(
      `${ATLASSIAN_AUTH_SERVER}/oauth/token`,
      body.toString(),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );
    // store tokens and expiry timestamp
    req.session.tokens = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + (data.expires_in - 60) * 1000, // refresh 60s early
    };
    res.redirect("/projects");
  } catch (err) {
    next(err);
  }
});

async function getAccessToken(req) {
  const tokens = req.session.tokens;
  if (!tokens) throw new Error("Not authenticated");
  if (tokens.expires_at && Date.now() < tokens.expires_at) {
    return tokens.access_token;
  }
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: process.env.ATLASSIAN_CLIENT_ID,
    client_secret: process.env.ATLASSIAN_CLIENT_SECRET,
    refresh_token: tokens.refresh_token,
  });
  const { data } = await axios.post(
    `${ATLASSIAN_AUTH_SERVER}/oauth/token`,
    body.toString(),
    {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    }
  );
  req.session.tokens = {
    access_token: data.access_token,
    refresh_token: data.refresh_token || tokens.refresh_token,
    expires_at: Date.now() + (data.expires_in - 60) * 1000,
  };
  return req.session.tokens.access_token;
}

async function getCloudId(req) {
  if (req.session.cloudId) return req.session.cloudId;
  const accessToken = await getAccessToken(req);
  const resp = await axios.get(
    `${ATLASSIAN_API}/oauth/token/accessible-resources`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );
  // Pick first Jira resource for simplicity
  const jiraSite = resp.data.find(
    (r) => r.scopes && r.scopes.length && r.id && r.url
  );
  if (!jiraSite) throw new Error("No accessible Jira site found");
  req.session.cloudId = jiraSite.id;
  return jiraSite.id;
}

async function getProjects(req) {
  const accessToken = await getAccessToken(req);
  const cloudId = await getCloudId(req);
  const url = `${ATLASSIAN_API}/ex/jira/${cloudId}/rest/api/3/project/search`;
  const { data } = await axios.get(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return data.values || [];
}

app.get("/projects", ensureAuth, async (req, res, next) => {
  try {
    const projects = await getProjects(req);
    res.render("projects", { projects });
  } catch (err) {
    next(err);
  }
});

app.get("/issues/new", ensureAuth, async (req, res, next) => {
  try {
    const projects = await getProjects(req);
    res.render("new-issue", { projects, error: null });
  } catch (err) {
    next(err);
  }
});

app.post("/issues", ensureAuth, async (req, res, next) => {
  try {
    const { projectKey, summary, description, issueType } = req.body;
    const accessToken = await getAccessToken(req);
    const cloudId = await getCloudId(req);
    const createUrl = `${ATLASSIAN_API}/ex/jira/${cloudId}/rest/api/3/issue`;

    const fields = {
      project: { key: projectKey },
      summary,
      issuetype: { name: issueType || "Task" },
    };
    if (description && description.trim().length > 0) {
      fields.description = {
        type: "doc",
        version: 1,
        content: [
          {
            type: "paragraph",
            content: [{ type: "text", text: description }],
          },
        ],
      };
    }

    await axios.post(
      createUrl,
      { fields },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );
    res.render("success");
  } catch (err) {
    let details =
      err && err.response && err.response.data
        ? JSON.stringify(err.response.data)
        : "";
    console.error("Create issue failed", details || err);
    try {
      const projects = await getProjects(req);
      res
        .status(400)
        .render("new-issue", {
          projects,
          error: details || err.message || "Failed to create issue",
        });
    } catch (_) {
      res
        .status(400)
        .render("new-issue", {
          projects: [],
          error: details || err.message || "Failed to create issue",
        });
    }
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// Basic error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res
    .status(500)
    .render("error", { message: err.message || "Unexpected error" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
