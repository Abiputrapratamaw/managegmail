import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { createOAuthState, exchangeCodeForTokens, getGoogleUserInfo, refreshGoogleAccessToken } from './lib/oauth';
import { initDatabase } from './lib/db';
import { buildGoogleAuthUrl, escapeHtml } from './lib/utils';
import { fetchInboxPage, fetchMessage, parseGmailMessage, fetchAttachment } from './lib/gmail';
import { sanitizeHtml } from './lib/security';

interface Env {
  DB: D1Database;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_REDIRECT_URI: string;
  SESSION_SECRET: string;
  TOKEN_ENCRYPTION_KEY: string;
  APP_BASE_URL: string;
}

interface SessionUser {
  id: string;
  gmail_email: string;
  display_name?: string;
  avatar_url?: string;
}

interface GmailAccountRecord {
  id: string;
  gmail_email: string;
  display_name: string | null;
  avatar_url: string | null;
  created_at: string;
}

const app = new Hono<{ Bindings: Env; Variables: { session?: SessionUser } }>();
const SESSION_COOKIE = 'avola_session';
const STATE_COOKIE = 'avola_oauth_state';
const DEFAULT_INBOX_LIMIT = 20;

function ensureRuntimeEnv(env: Env) {
  const required = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI', 'SESSION_SECRET', 'TOKEN_ENCRYPTION_KEY', 'APP_BASE_URL'];
  for (const key of required) {
    if (!env[key as keyof Env]) {
      throw new Error(`Missing environment: ${key}`);
    }
  }
}

async function ensureDb(env: Env) {
  await initDatabase(env.DB);
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new Uint8Array(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
}

async function encryptValue(value: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const normalizedKey = secret.padEnd(32, '0').slice(0, 32);
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(normalizedKey), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode('avola-gmail-manager'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(value));
  const ivValue = toBase64(iv);
  const encryptedValue = toBase64(new Uint8Array(encrypted));
  return `${ivValue}:${encryptedValue}`;
}

async function decryptValue(value: string, secret: string): Promise<string> {
  const [ivValue, encryptedValue] = value.split(':');
  if (!ivValue || !encryptedValue) {
    throw new Error('Invalid encrypted payload');
  }

  const encoder = new TextEncoder();
  const normalizedKey = secret.padEnd(32, '0').slice(0, 32);
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(normalizedKey), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode('avola-gmail-manager'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );

  const ivBytes = new Uint8Array(fromBase64(ivValue));
  const encryptedBytes = new Uint8Array(fromBase64(encryptedValue));

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes },
    key,
    encryptedBytes,
  );

  return new TextDecoder().decode(decrypted);
}

function getSessionFromCookie(raw: string | null): SessionUser | null {
  if (!raw) return null;
  try {
    return JSON.parse(atob(raw)) as SessionUser;
  } catch {
    return null;
  }
}

async function getCurrentUser(c: any): Promise<SessionUser | null> {
  const sessionValue = getCookie(c, SESSION_COOKIE);
  if (!sessionValue) return null;
  return getSessionFromCookie(sessionValue);
}

async function requireAuth(c: any, next: any) {
  const user = await getCurrentUser(c);
  if (!user) {
    return c.redirect('/');
  }
  c.set('session', user);
  await next();
}

function renderLandingPage(): string {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Avola Gmail Manager</title>
        <style>
          :root {
            --bg: #081120;
            --bg-soft: #101b2e;
            --panel: rgba(255,255,255,0.05);
            --panel-border: rgba(255,255,255,0.12);
            --primary: #6ea8fe;
            --primary-strong: #3d82ff;
            --text: #edf4ff;
            --muted: #b8c3d8;
          }
          * { box-sizing: border-box; }
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: radial-gradient(circle at top, #14243f, var(--bg));
            color: var(--text);
            font-family: Inter, Arial, sans-serif;
          }
          .card {
            width: min(560px, 92vw);
            padding: 40px 36px;
            border-radius: 24px;
            background: var(--panel);
            border: 1px solid var(--panel-border);
            box-shadow: 0 30px 80px rgba(0,0,0,0.38);
          }
          .eyebrow {
            display: inline-block;
            font-size: 11px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--primary);
            margin-bottom: 16px;
          }
          h1 {
            margin: 0 0 18px;
            font-size: clamp(2rem, 5vw, 3rem);
            line-height: 1.1;
          }
          p {
            color: var(--muted);
            line-height: 1.7;
            margin-bottom: 28px;
          }
          .button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            background: linear-gradient(135deg, var(--primary), var(--primary-strong));
            color: white;
            text-decoration: none;
            font-weight: 700;
            border-radius: 12px;
            padding: 16px 22px;
            box-shadow: 0 12px 30px rgba(61,130,255,0.35);
          }
          .meta {
            margin-top: 22px;
            font-size: 12px;
            color: var(--muted);
          }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="eyebrow">Avola Mail</div>
          <h1>Read Gmail securely, one account at a time.</h1>
          <p>
            Connect your Gmail account with Google OAuth 2.0 and access your inbox directly from Gmail API.
            This app keeps each account isolated and stores tokens securely in Cloudflare D1.
          </p>
          <a class="button" href="/auth/google">Connect Gmail / Sign in with Google</a>
          <div class="meta">OAuth scope: gmail.readonly</div>
        </div>
      </body>
    </html>
  `;
}

function renderDashboardPage(userEmail: string): string {
  const safeEmail = escapeHtml(userEmail || 'User');
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Avola Inbox</title>
        <style>
          :root {
            --bg: #eef4fb;
            --panel: #ffffff;
            --panel-alt: #f8fafd;
            --sidebar: #0f172a;
            --sidebar-muted: #a5b4cf;
            --border: #dde5f0;
            --text: #18212f;
            --muted: #61708a;
            --primary: #3a7afe;
            --success: #1a9d5c;
            --shadow: 0 30px 60px rgba(15, 23, 42, 0.08);
          }
          * { box-sizing: border-box; }
          html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: Inter, Arial, sans-serif; }
          body { min-height: 100vh; }
          .topbar {
            height: 72px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--sidebar);
            color: white;
            padding: 0 24px;
            box-shadow: 0 12px 24px rgba(15, 23, 42, 0.12);
          }
          .brand {
            font-weight: 800;
            letter-spacing: 0.04em;
          }
          .account-chip {
            background: rgba(255,255,255,0.08);
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 13px;
          }
          .layout {
            display: grid;
            grid-template-columns: 240px 1fr;
            min-height: calc(100vh - 72px);
          }
          .sidebar {
            background: #e9eef8;
            border-right: 1px solid var(--border);
            padding: 20px 18px;
          }
          .nav-item {
            display: block;
            padding: 12px 14px;
            border-radius: 12px;
            background: white;
            color: var(--text);
            border: 1px solid var(--border);
            text-decoration: none;
            margin-bottom: 10px;
            font-weight: 600;
          }
          .nav-item.warn {
            background: rgba(58, 122, 254, 0.08);
            color: var(--primary);
            border-color: rgba(58, 122, 254, 0.15);
          }
          .main {
            padding: 24px;
          }
          .panel {
            background: var(--panel);
            border-radius: 18px;
            border: 1px solid var(--border);
            box-shadow: var(--shadow);
            padding: 18px 0;
            overflow: hidden;
          }
          .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px 16px;
            border-bottom: 1px solid var(--border);
          }
          .title {
            margin: 0;
            font-size: 1.4rem;
          }
          .pill {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            background: rgba(26, 157, 92, 0.1);
            color: var(--success);
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
          }
          #inbox-root {
            background: white;
          }
          .mail-row {
            display: grid;
            grid-template-columns: 1.2fr 2fr 2fr 0.9fr;
            gap: 14px;
            padding: 14px 20px;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
          }
          .mail-row:hover { background: var(--panel-alt); }
          .mail-row strong { font-weight: 700; }
          .muted { color: var(--muted); }
          .badge {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            background: rgba(58, 122, 254, 0.08);
            color: var(--primary);
            padding: 5px 8px;
            font-size: 11px;
            font-weight: 700;
          }
          @media (max-width: 900px) {
            .layout { grid-template-columns: 1fr; }
            .sidebar { border-right: 0; border-bottom: 1px solid var(--border); }
            .mail-row { grid-template-columns: 1fr; }
          }
        </style>
      </head>
      <body>
        <div class="topbar">
          <div class="brand">Avola Mail</div>
          <div class="account-chip">${safeEmail}</div>
        </div>
        <div class="layout">
          <aside class="sidebar">
            <a class="nav-item warn" href="/dashboard">Inbox</a>
            <a class="nav-item" href="/logout">Logout</a>
          </aside>
          <main class="main">
            <div class="panel">
              <div class="panel-header">
                <h2 class="title">Inbox</h2>
                <span class="pill">Live Gmail</span>
              </div>
              <div id="inbox-root"></div>
            </div>
          </main>
        </div>
        <script>
          async function loadInbox() {
            const root = document.getElementById('inbox-root');
            try {
              const res = await fetch('/api/inbox');
              const data = await res.json();
              if (!Array.isArray(data.messages) || data.messages.length === 0) {
                root.innerHTML = '<div style="padding: 24px; color: #61708a;">No messages found.</div>';
                return;
              }

              root.innerHTML = data.messages.map(function (m) {
                const sender = (m.from || 'Unknown sender').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                const subject = (m.subject || '(no subject)').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                const snippet = (m.snippet || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                const badge = m.attachmentCount > 0 ? '<span class="badge">Attachment</span>' : '<span class="badge">Mail</span>';
                return '<div class="mail-row" data-id="' + m.id + '">' +
                  '<div><strong>' + sender + '</strong></div>' +
                  '<div>' + subject + '</div>' +
                  '<div class="muted">' + snippet + '</div>' +
                  '<div style="text-align:right;">' + (m.date || '') + '<br />' + badge + '</div>' +
                  '</div>';
              }).join('');

              root.querySelectorAll('.mail-row').forEach(function (row) {
                row.addEventListener('click', function () {
                  const id = row.getAttribute('data-id');
                  if (id) {
                    window.location.href = '/mail/' + id;
                  }
                });
              });
            } catch (error) {
              root.innerHTML = '<div style="padding: 24px; color: #b42318;">Failed to load inbox.</div>';
            }
          }

          loadInbox();
        </script>
      </body>
    </html>
  `;
}

async function renderMessagePage(message: { subject: string; from: string; to: string; cc: string; bcc: string; date: string; body: string; htmlBody?: string; attachments: Array<{ filename: string; mimeType: string; attachmentId?: string }> }): Promise<string> {
  const subject = escapeHtml(message.subject || '(no subject)');
  const from = escapeHtml(message.from || '');
  const to = escapeHtml(message.to || '');
  const cc = escapeHtml(message.cc || '');
  const bcc = escapeHtml(message.bcc || '');
  const date = escapeHtml(message.date || '');
  const fallbackBody = '<pre style="white-space: pre-wrap; word-break: break-word; margin: 0; font-family: inherit;">' + escapeHtml(message.body || '') + '</pre>';
  const safeHtmlBody = message.htmlBody ? await sanitizeHtml(message.htmlBody) : fallbackBody;

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>${subject}</title>
        <style>
          :root {
            --bg: #eef4fb;
            --panel: #ffffff;
            --border: #dde5f0;
            --text: #18212f;
            --muted: #61708a;
            --primary: #3a7afe;
          }
          * { box-sizing: border-box; }
          body { margin: 0; font-family: Inter, Arial, sans-serif; background: var(--bg); color: var(--text); }
          .container {
            width: min(1100px, 94vw);
            margin: 32px auto;
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 20px;
            box-shadow: 0 18px 40px rgba(15, 23, 42, 0.08);
            overflow: hidden;
          }
          .header {
            padding: 24px 26px;
            border-bottom: 1px solid var(--border);
            background: linear-gradient(180deg, #f9fbff, #fff);
          }
          .subject {
            margin: 0 0 12px;
            font-size: clamp(1.4rem, 2vw, 2.1rem);
          }
          .meta {
            display: grid;
            gap: 8px;
            color: var(--muted);
            font-size: 14px;
          }
          .body {
            padding: 28px 26px 18px;
            line-height: 1.7;
            overflow: auto;
          }
          .body img { max-width: 100%; }
          .body a { color: var(--primary); }
          .attachments {
            border-top: 1px solid var(--border);
            padding: 18px 26px 26px;
          }
          .attachments h3 { margin: 0 0 12px; }
          .chip {
            display: inline-flex;
            margin: 8px 8px 0 0;
            padding: 8px 12px;
            border-radius: 999px;
            border: 1px solid var(--border);
            background: #f8fafc;
            font-size: 13px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1 class="subject">${subject}</h1>
            <div class="meta">
              <div><strong>From:</strong> ${from}</div>
              <div><strong>To:</strong> ${to || '—'}</div>
              <div><strong>Cc:</strong> ${cc || '—'}</div>
              <div><strong>Bcc:</strong> ${bcc || '—'}</div>
              <div><strong>Date:</strong> ${date || '—'}</div>
            </div>
          </div>
          <div class="body">${safeHtmlBody}</div>
          <div class="attachments">
            <h3>Attachments</h3>
            ${message.attachments.length ? message.attachments.map((item) => `<span class="chip">${escapeHtml(item.filename || 'Attachment')}</span>`).join('') : '<span class="muted">No attachments</span>'}
          </div>
        </div>
      </body>
    </html>
  `;
}

async function getAccessTokenForUser(env: Env, gmailEmail: string): Promise<string> {
  const record = await env.DB.prepare('SELECT * FROM user_credentials WHERE gmail_email = ?').bind(gmailEmail).first();
  if (!record) {
    throw new Error('Account not found');
  }

  const accessText = await decryptValue(String(record.access_token_encrypted), env.TOKEN_ENCRYPTION_KEY);
  const accessPayload = JSON.parse(accessText) as { token: string; expiry: number };
  const now = Date.now();

  if (accessPayload.expiry > now) {
    return accessPayload.token;
  }

  const refreshText = await decryptValue(String(record.refresh_token_encrypted), env.TOKEN_ENCRYPTION_KEY);
  const refreshPayload = JSON.parse(refreshText) as { token: string };
  if (!refreshPayload.token) {
    throw new Error('Refresh token unavailable');
  }

  const refreshed = await refreshGoogleAccessToken(refreshPayload.token);
  const newAccess = {
    token: refreshed.access_token,
    expiry: now + (refreshed.expires_in ?? 3600) * 1000,
  };

  await env.DB.prepare('UPDATE user_credentials SET access_token_encrypted = ?, expiry_date = ?, updated_at = ? WHERE gmail_email = ?')
    .bind(
      await encryptValue(JSON.stringify(newAccess), env.TOKEN_ENCRYPTION_KEY),
      new Date(Date.now() + (refreshed.expires_in ?? 3600) * 1000).toISOString(),
      new Date().toISOString(),
      gmailEmail,
    )
    .run();

  return refreshed.access_token;
}

app.use('*', async (c, next) => {
  ensureRuntimeEnv(c.env);
  await ensureDb(c.env);
  await next();
});

app.get('/', async (c) => {
  const user = await getCurrentUser(c);
  if (user) {
    return c.redirect('/dashboard');
  }
  return c.html(renderLandingPage());
});

app.get('/auth/google', async (c) => {
  const state = createOAuthState();
  const expiresAt = Date.now() + 10 * 60 * 1000;
  const stateHash = btoa(JSON.stringify({ state, exp: expiresAt }));
  const redirectUrl = buildGoogleAuthUrl(state, c.env.GOOGLE_REDIRECT_URI, c.env.GOOGLE_CLIENT_ID);

  await c.env.DB.prepare('INSERT INTO oauth_state (id, state, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(crypto.randomUUID(), state, new Date().toISOString(), new Date(expiresAt).toISOString())
    .run();

  const response = c.redirect(redirectUrl);
  response.headers.append('Set-Cookie', `${STATE_COOKIE}=${encodeURIComponent(stateHash)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`);
  return response;
});

app.get('/auth/google/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const cookieState = getCookie(c, STATE_COOKIE);

  if (!code || !state || !cookieState) {
    return c.redirect('/?error=oauth_invalid');
  }

  try {
    const decoded = JSON.parse(atob(cookieState)) as { state: string; exp: number };
    if (decoded.state !== state || decoded.exp < Date.now()) {
      return c.redirect('/?error=oauth_invalid_state');
    }

    const stored = await c.env.DB.prepare('SELECT * FROM oauth_state WHERE state = ? AND expires_at > ? LIMIT 1').bind(state, new Date().toISOString()).first();
    if (!stored) {
      return c.redirect('/?error=oauth_state_missing');
    }
  } catch {
    return c.redirect('/?error=oauth_invalid_state');
  }

  try {
    const token = await exchangeCodeForTokens(code, c.env.GOOGLE_REDIRECT_URI);
    const userInfo = await getGoogleUserInfo(token.access_token);

    const existing = await c.env.DB.prepare('SELECT * FROM users WHERE gmail_email = ?').bind(userInfo.email).first() as GmailAccountRecord | null;
    const userId = existing?.id ?? crypto.randomUUID();

    if (!existing) {
      await c.env.DB.prepare('INSERT INTO users (id, gmail_email, display_name, avatar_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(userId, userInfo.email, userInfo.name ?? userInfo.email, userInfo.picture ?? '', new Date().toISOString(), new Date().toISOString())
        .run();
    }

    const accessPayload = JSON.stringify({ token: token.access_token, expiry: Date.now() + (token.expires_in ?? 3600) * 1000 });
    const refreshPayload = JSON.stringify({ token: token.refresh_token ?? '' });

    await c.env.DB.prepare(`
      INSERT INTO user_credentials (id, user_id, gmail_email, access_token_encrypted, refresh_token_encrypted, token_type, expiry_date, scopes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, gmail_email) DO UPDATE SET
        access_token_encrypted = excluded.access_token_encrypted,
        refresh_token_encrypted = excluded.refresh_token_encrypted,
        token_type = excluded.token_type,
        expiry_date = excluded.expiry_date,
        scopes = excluded.scopes,
        updated_at = excluded.updated_at
    `)
      .bind(
        crypto.randomUUID(),
        userId,
        userInfo.email,
        await encryptValue(accessPayload, c.env.TOKEN_ENCRYPTION_KEY),
        await encryptValue(refreshPayload, c.env.TOKEN_ENCRYPTION_KEY),
        token.token_type ?? 'Bearer',
        new Date(Date.now() + (token.expires_in ?? 3600) * 1000).toISOString(),
        token.scope ?? 'https://www.googleapis.com/auth/gmail.readonly',
        new Date().toISOString(),
        new Date().toISOString(),
      )
      .run();

    const sessionPayload = {
      id: userId,
      gmail_email: userInfo.email,
      display_name: userInfo.name ?? userInfo.email,
      avatar_url: userInfo.picture ?? '',
    };

    const response = c.redirect('/dashboard');
    response.headers.append('Set-Cookie', `${STATE_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
    response.headers.append('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(btoa(JSON.stringify(sessionPayload)))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);
    return response;
  } catch (error) {
    console.error('OAuth callback error', error);
    return c.redirect('/?error=oauth_failed');
  }
});

app.get('/dashboard', requireAuth, async (c) => {
  const user = c.get('session');
  return c.html(renderDashboardPage(user?.gmail_email ?? 'User'));
});

app.get('/mail/:id', requireAuth, async (c) => {
  const user = c.get('session');
  const messageId = c.req.param('id');
  const accessToken = await getAccessTokenForUser(c.env, user!.gmail_email);
  const rawMessage = await fetchMessage(accessToken, messageId);
  const parsed = parseGmailMessage(rawMessage);
  const safeBody = parsed.htmlBody ? await sanitizeHtml(parsed.htmlBody) : `<pre style="white-space: pre-wrap; word-break: break-word; margin: 0; font-family: inherit;">${escapeHtml(parsed.body || '')}</pre>`;

  const page = await renderMessagePage({
    subject: parsed.subject,
    from: parsed.from,
    to: parsed.to,
    cc: parsed.cc,
    bcc: parsed.bcc,
    date: parsed.date,
    body: parsed.body,
    htmlBody: safeBody,
    attachments: parsed.attachments,
  });

  return c.html(page);
});

app.get('/api/me', requireAuth, async (c) => {
  const user = c.get('session');
  return c.json({ user });
});

app.get('/api/accounts', requireAuth, async (c) => {
  const rows = await c.env.DB.prepare('SELECT id, gmail_email, display_name, avatar_url, created_at FROM users ORDER BY created_at DESC').all();
  return c.json({ accounts: rows.results ?? [] });
});

app.get('/api/inbox', requireAuth, async (c) => {
  const user = c.get('session');
  const accessToken = await getAccessTokenForUser(c.env, user!.gmail_email);
  const pageToken = c.req.query('pageToken') ?? undefined;
  const maxResults = Number(c.req.query('maxResults') ?? String(DEFAULT_INBOX_LIMIT));

  const inbox = await fetchInboxPage(accessToken, { maxResults, pageToken });
  const messageIds = inbox.messages ?? [];

  const items = await Promise.all(
    messageIds.map(async (item) => {
      const message = await fetchMessage(accessToken, item.id);
      const parsed = parseGmailMessage(message);
      return {
        id: item.id,
        threadId: item.threadId,
        from: parsed.from,
        subject: parsed.subject,
        date: parsed.date,
        snippet: parsed.snippet ?? parsed.body.slice(0, 180),
        unread: Array.isArray(item.labelIds) ? !item.labelIds.includes('READ') : true,
        attachmentCount: parsed.attachments.length,
      };
    }),
  );

  return c.json({
    messages: items,
    nextPageToken: inbox.nextPageToken ?? null,
    resultSizeEstimate: inbox.resultSizeEstimate ?? items.length,
  });
});

app.get('/api/messages/:id', requireAuth, async (c) => {
  const user = c.get('session');
  const accessToken = await getAccessTokenForUser(c.env, user!.gmail_email);
  const messageId = c.req.param('id');
  const detail = await fetchMessage(accessToken, messageId);
  const parsed = parseGmailMessage(detail);

  return c.json({
    message: {
      id: parsed.id,
      threadId: parsed.threadId,
      subject: parsed.subject,
      from: parsed.from,
      to: parsed.to,
      cc: parsed.cc,
      bcc: parsed.bcc,
      date: parsed.date,
      body: parsed.body,
      htmlBody: parsed.htmlBody,
      plainBody: parsed.plainBody,
      attachments: parsed.attachments,
      snippet: parsed.snippet,
      headers: parsed.headers,
      labels: parsed.labels,
    },
  });
});

app.get('/api/messages/:id/attachments/:attachmentId', requireAuth, async (c) => {
  const user = c.get('session');
  const accessToken = await getAccessTokenForUser(c.env, user!.gmail_email);
  const messageId = c.req.param('id');
  const attachmentId = c.req.param('attachmentId');
  const attachment = await fetchAttachment(accessToken, messageId, attachmentId);
  return c.json({ attachment });
});

app.get('/logout', async (c) => {
  const response = c.redirect('/');
  response.headers.append('Set-Cookie', `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
  response.headers.append('Set-Cookie', `${STATE_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
  return response;
});

app.onError((err, c) => {
  console.error('Unhandled worker error', err);
  return c.text('Internal server error', 500);
});

export default app;
