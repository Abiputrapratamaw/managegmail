import { getEnv } from './utils';

export function getCookieHeader(cookies: string | null, name: string): string | null {
  if (!cookies) return null;
  const entries = cookies.split(';').map((v) => v.trim());
  for (const entry of entries) {
    const equalsIndex = entry.indexOf('=');
    if (equalsIndex === -1) continue;
    const key = entry.slice(0, equalsIndex);
    const value = entry.slice(equalsIndex + 1);
    if (key === name) return decodeURIComponent(value);
  }
  return null;
}

export function setCookie(name: string, value: string, options: { httpOnly?: boolean; secure?: boolean; sameSite?: 'Lax' | 'Strict' | 'None'; path?: string; maxAge?: number }): string {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${options.path ?? '/'}`);
  if (options.httpOnly) parts.push('HttpOnly');
  if (options.secure) parts.push('Secure');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (typeof options.maxAge === 'number') parts.push(`Max-Age=${options.maxAge}`);
  return parts.join('; ');
}

export function parseSignedState(raw: string): { state: string; expiresAt: number } | null {
  try {
    const decoded = atob(raw);
    const [state, expiresAt] = decoded.split('::');
    if (!state || !expiresAt) return null;
    return { state, expiresAt: Number(expiresAt) };
  } catch {
    return null;
  }
}

export function createSignedStateCookie(state: string): string {
  const expiresAt = Date.now() + 10 * 60 * 1000;
  const secret = getEnv('SESSION_SECRET');
  const payload = btoa(`${state}::${expiresAt}::${secret.slice(0, 12)}`);
  return payload;
}

export function validateSignedState(raw: string): boolean {
  const parsed = parseSignedState(raw);
  if (!parsed) return false;
  return parsed.expiresAt > Date.now();
}

export async function sanitizeHtml(input: string): Promise<string> {
  const sanitize = (await import('sanitize-html')).default;
  return sanitize(input, {
    allowedTags: [
      'a', 'b', 'blockquote', 'br', 'code', 'del', 'div', 'em', 'font', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'hr', 'i', 'img', 'li', 'ol', 'p', 'pre', 's', 'span', 'strong', 'table', 'tbody', 'td', 'th', 'thead',
      'tr', 'u', 'ul', 'section', 'article', 'header', 'footer', 'main', 'small'
    ],
    allowedAttributes: {
      a: ['href', 'target', 'rel'],
      img: ['src', 'alt', 'title'],
      '*': ['style'],
    },
    transformTags: {
      a: (tagName, attribs) => ({
        tagName,
        attribs: {
          ...attribs,
          target: '_blank',
          rel: 'noopener noreferrer nofollow',
        },
      }),
    },
  });
}
