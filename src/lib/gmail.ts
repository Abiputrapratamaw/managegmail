export interface GmailMessageHeader {
  name: string;
  value: string;
}

export interface GmailMessagePart {
  partId?: string;
  mimeType?: string;
  filename?: string;
  headers?: GmailMessageHeader[];
  body?: {
    size?: number;
    data?: string;
    attachmentId?: string;
  };
  parts?: GmailMessagePart[];
}

export interface GmailMessage {
  id: string;
  threadId?: string;
  labelIds?: string[];
  payload?: {
    mimeType?: string;
    headers?: GmailMessageHeader[];
    body?: { data?: string };
    parts?: GmailMessagePart[];
  };
  snippet?: string;
  sizeEstimate?: number;
}

export interface GmailMessageListItem {
  id: string;
  threadId?: string;
  labelIds?: string[];
  snippet?: string;
  payload?: {
    headers?: GmailMessageHeader[];
  };
}

export interface ParsedAttachment {
  partId?: string;
  filename: string;
  mimeType: string;
  attachmentId?: string;
  size?: number;
}

export interface ParsedMessage {
  id: string;
  threadId?: string;
  subject: string;
  from: string;
  to: string;
  cc: string;
  bcc: string;
  date: string;
  body: string;
  htmlBody?: string;
  plainBody?: string;
  attachments: ParsedAttachment[];
  snippet?: string;
  headers: Record<string, string>;
  labels?: string[];
  hasAttachments: boolean;
}

function parseHeaders(headers: GmailMessageHeader[] = []): Record<string, string> {
  return headers.reduce((acc, header) => {
    acc[header.name.toLowerCase()] = header.value;
    return acc;
  }, {} as Record<string, string>);
}

function decodeBodyData(data?: string): string {
  if (!data) return '';
  const normalized = data.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const raw = atob(normalized + pad);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    bytes[i] = raw.charCodeAt(i);
  }
  return new TextDecoder('utf-8').decode(bytes);
}

function collectMimeParts(part: GmailMessagePart | undefined): GmailMessagePart[] {
  if (!part) return [];
  const results: GmailMessagePart[] = [];
  if (part.parts?.length) {
    for (const child of part.parts) {
      results.push(...collectMimeParts(child));
    }
  }
  results.push(part);
  return results;
}

function getPartContent(part: GmailMessagePart): string {
  if (part.body?.data) {
    return decodeBodyData(part.body.data);
  }
  return '';
}

function findPreferredBody(part: GmailMessagePart | undefined): { plain: string; html: string } {
  const plainParts: string[] = [];
  const htmlParts: string[] = [];
  const parts = collectMimeParts(part);

  for (const item of parts) {
    const mimeType = item.mimeType ?? '';
    if (item.body?.data) {
      if (mimeType.includes('text/plain')) plainParts.push(getPartContent(item));
      if (mimeType.includes('text/html')) htmlParts.push(getPartContent(item));
    }
  }

  return {
    plain: plainParts.join('\n\n'),
    html: htmlParts.join('\n\n'),
  };
}

export function parseGmailMessage(raw: GmailMessage): ParsedMessage {
  const headers = parseHeaders(raw.payload?.headers ?? []);
  const attachments: ParsedAttachment[] = [];

  function traverse(node: GmailMessagePart | undefined) {
    if (!node) return;

    const mimeType = node.mimeType ?? '';
    const filename = node.filename ?? '';
    const attachmentId = node.body?.attachmentId;

    if (attachmentId || filename) {
      attachments.push({
        partId: node.partId,
        filename: filename || 'attachment',
        mimeType: mimeType || 'application/octet-stream',
        attachmentId,
        size: node.body?.size,
      });
    }

    if (node.parts) {
      for (const part of node.parts) {
        traverse(part);
      }
    }
  }

  traverse(raw.payload);

  const selected = findPreferredBody(raw.payload);
  const plainBody = selected.plain || '';
  const htmlBody = selected.html || '';

  const message: ParsedMessage = {
    id: raw.id,
    threadId: raw.threadId,
    subject: headers.subject || '(no subject)',
    from: headers.from || '',
    to: headers.to || '',
    cc: headers.cc || '',
    bcc: headers.bcc || '',
    date: headers.date || '',
    body: plainBody || htmlBody || '',
    htmlBody: htmlBody || undefined,
    plainBody: plainBody || undefined,
    attachments,
    snippet: raw.snippet,
    headers,
    labels: raw.labelIds,
    hasAttachments: attachments.length > 0,
  };

  return message;
}

export async function fetchInboxPage(accessToken: string, options: { q?: string; maxResults?: number; pageToken?: string } = {}) {
  const params = new URLSearchParams({
    includeSpamTrash: 'false',
    maxResults: String(options.maxResults ?? 20),
  });

  if (options.q) params.set('q', options.q);
  if (options.pageToken) params.set('pageToken', options.pageToken);

  const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages?${params.toString()}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Gmail inbox fetch failed: ${response.status} ${errorText}`);
  }

  return response.json() as Promise<{ messages?: GmailMessageListItem[]; nextPageToken?: string; resultSizeEstimate?: number }>;
}

export async function fetchMessage(accessToken: string, messageId: string) {
  const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Gmail message fetch failed: ${response.status} ${errorText}`);
  }

  return response.json() as Promise<GmailMessage>;
}

export async function fetchAttachment(accessToken: string, messageId: string, attachmentId: string) {
  const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/attachments/${attachmentId}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Gmail attachment fetch failed: ${response.status} ${errorText}`);
  }

  return response.json() as Promise<{ data?: string; size?: number; mimeType?: string; filename?: string }>;
}
