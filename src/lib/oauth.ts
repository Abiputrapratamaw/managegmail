import { getEnv } from './utils';

export interface GoogleTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
  id_token?: string;
}

export type GoogleError = {
  error: string;
  error_description?: string;
};

export async function exchangeCodeForTokens(code: string, redirectUri: string): Promise<GoogleTokenResponse> {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      code,
      client_id: getEnv('GOOGLE_CLIENT_ID'),
      client_secret: getEnv('GOOGLE_CLIENT_SECRET'),
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });

  const payload = (await response.json()) as GoogleTokenResponse | GoogleError;
  if (!response.ok || 'error' in payload) {
    throw new Error(`Token exchange failed: ${('error' in payload ? payload.error : response.statusText) || 'unknown error'}`);
  }

  return payload;
}

export async function getGoogleUserInfo(accessToken: string): Promise<{ id: string; email: string; name?: string; picture?: string }> {
  const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch Google user info: ${response.status}`);
  }

  return response.json();
}

export async function refreshGoogleAccessToken(refreshToken: string): Promise<GoogleTokenResponse> {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: getEnv('GOOGLE_CLIENT_ID'),
      client_secret: getEnv('GOOGLE_CLIENT_SECRET'),
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    }),
  });

  const payload = (await response.json()) as GoogleTokenResponse | GoogleError;
  if (!response.ok || 'error' in payload) {
    throw new Error(`Refresh token failed: ${('error' in payload ? payload.error : response.statusText) || 'unknown error'}`);
  }

  return payload;
}

export function createOAuthState(): string {
  return crypto.randomUUID();
}
