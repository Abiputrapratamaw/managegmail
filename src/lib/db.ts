export interface D1DatabaseLike {
  prepare(query: string): { bind(...args: any[]): any; all(): Promise<any>; first(): Promise<any>; run(): Promise<any>; };
  exec(query: string): Promise<any>;
}

export const DB_SCHEMA = `
CREATE TABLE IF NOT EXISTS oauth_state (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  gmail_email TEXT NOT NULL UNIQUE,
  display_name TEXT,
  avatar_url TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  session_token TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  user_agent TEXT,
  ip_address TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS user_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  gmail_email TEXT NOT NULL,
  access_token_encrypted TEXT NOT NULL,
  refresh_token_encrypted TEXT NOT NULL,
  token_type TEXT,
  expiry_date TEXT,
  scopes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, gmail_email),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS oauth_events (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  gmail_email TEXT,
  event_type TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`;

export async function initDatabase(db: D1DatabaseLike) {
  await db.exec(DB_SCHEMA);
}

export function toSqlDate(date: Date): string {
  return date.toISOString();
}
