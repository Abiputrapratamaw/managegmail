# Avola Gmail Manager

Avola Gmail Manager is a Cloudflare Worker-based web application for connecting multiple Gmail accounts using Google OAuth 2.0 and reading inbox content directly from the Gmail API.

## Features

- Google OAuth 2.0 and Gmail API integration
- Secure multi-account support with isolated Gmail credentials per account
- Server-side session and token management
- Inbox listing with Gmail pagination
- Full email body rendering without truncation or summary generation
- Safe HTML sanitization for Gmail HTML bodies
- D1 storage schema ready for Cloudflare deployment
- Modern responsive mail-client interface

## Requirements

- Node.js 20+
- Cloudflare account
- Google Cloud Console project with OAuth 2.0 Client ID
- Cloudflare D1 database
- Domain configured to point to Cloudflare Workers

## Install dependencies

```bash
npm install
```

## Environment variables

Copy `.dev.vars.example` to `.dev.vars` and fill in real values.

```bash
cp .dev.vars.example .dev.vars
```

Required environment variables:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI`
- `SESSION_SECRET`
- `TOKEN_ENCRYPTION_KEY`
- `APP_BASE_URL`

Important:

- Do not hardcode the Google Client Secret in frontend code.
- Do not expose OAuth tokens to the frontend.
- Keep the redirect URI exactly as configured in Google OAuth.

## Cloudflare setup

### 1) Login to Cloudflare

```bash
npx wrangler login
```

### 2) Create a D1 database

```bash
npx wrangler d1 create avola-gmail-manager
```

Copy the returned `database_id` into `wrangler.jsonc`.

### 3) Apply database migrations

```bash
npx wrangler d1 migrations apply avola-gmail-manager --local
```

For a live deployment:

```bash
npx wrangler d1 migrations apply avola-gmail-manager
```

### 4) Set Cloudflare secrets

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put GOOGLE_REDIRECT_URI
npx wrangler secret put SESSION_SECRET
npx wrangler secret put TOKEN_ENCRYPTION_KEY
```

If you want local development only, use `.dev.vars`.

## Google OAuth configuration

In Google Cloud Console:

1. Create a Google Cloud project.
2. Enable the Gmail API.
3. Create an OAuth 2.0 Client ID.
4. Choose Application type: Web application.
5. Add authorized redirect URI:

```text
https://manage.avola.id/auth/google/callback
```

6. Add the required scope:

```text
https://www.googleapis.com/auth/gmail.readonly
```

7. Save the client ID and client secret.

## Local development

```bash
npm run dev
```

Then open:

```text
http://localhost:8787
```

## Production deployment

```bash
npm run deploy
```

After deployment, configure the custom domain `manage.avola.id` in Cloudflare.

## Application flow

1. User clicks Connect Gmail.
2. Worker redirects to Google OAuth authorization endpoint.
3. Google redirects back to `/auth/google/callback` with `code` and `state`.
4. Worker validates `state` and exchanges the code for tokens.
5. Worker calls Gmail profile endpoint to resolve the connected Gmail account.
6. Tokens are stored encrypted and associated with that Gmail account.
7. Worker creates a secure app session and redirects to the dashboard.

## API routes

- `GET /auth/google`
- `GET /auth/google/callback`
- `GET /api/me`
- `GET /api/accounts`
- `GET /api/inbox`
- `GET /api/messages/:id`
- `GET /api/messages/:id/attachments/:attachmentId`
- `GET /logout`

## Security notes

- OAuth state is validated against a signed cookie and D1 record.
- Tokens are never exposed to the frontend.
- Session cookies are HttpOnly, Secure, and SameSite=Lax.
- Gmail account data is isolated by `user_id` and `gmail_email`.
- HTML email content is sanitized before rendering to reduce XSS risk.

## Full email rendering requirement

This app prioritizes the complete original Gmail body. It does not truncate, summarize, rewrite, or replace the email content with a snippet when the message is opened.

The app traverses the Gmail MIME structure recursively and renders:

- `text/plain`
- `text/html`
- `multipart/alternative`
- `multipart/mixed`
- nested multipart payloads
- attachment metadata

For HTML parts, the app sanitizes the content before rendering to protect against XSS while preserving the original email body.

## Important warnings

- Do not use a Gmail username/password login flow.
- Do not use API key authentication as a substitute for OAuth.
- Do not hardcode `GOOGLE_CLIENT_SECRET` or refresh tokens in the frontend.
- Do not replace a full email body with the Gmail `snippet` field.

## Troubleshooting

### OAuth redirect mismatch

- Ensure that `GOOGLE_REDIRECT_URI` in Google Cloud exactly matches:

```text
https://manage.avola.id/auth/google/callback
```

### Gmail API access denied

- Confirm the Gmail API is enabled.
- Confirm the OAuth scope is set to `https://www.googleapis.com/auth/gmail.readonly`.
- Confirm the user grants consent.

### Token refresh failure

- Confirm `refresh_token` is stored and not lost.
- Confirm the cloud secret `TOKEN_ENCRYPTION_KEY` is configured.

### D1 sqlite error

- Check that the database exists and the ID in `wrangler.jsonc` matches the real Cloudflare D1 database ID.

## License

MIT
