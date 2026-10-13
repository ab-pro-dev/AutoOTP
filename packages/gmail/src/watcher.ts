import { extractOtp } from "@autootp/otp-parser";
import { getHomeDir } from "@autootp/shared";
import { OAuthCredentials } from "./credentials.js";
import { refreshAccessToken } from "./login.js";
import { ReauthRequiredError } from "./errors.js";

export interface OtpNotification {
  accountId: string;
  sender: string;
  code: string;
  raw: string;
  confidence: "high" | "medium";
  receivedAt: number;
}

export interface WatchAccountOptions {
  accountId: string;
  onOtp: (otp: OtpNotification) => void | Promise<void>;
  onError?: (err: Error) => void | Promise<void>;
  pollMs?: number;
  signal?: AbortSignal;
  fetchImpl?: typeof fetch;
  homeDir?: string;
  credentials?: OAuthCredentials;
  initialBackoffMs?: number;
  maxBackoffMs?: number;
}

export interface GmailMessagePart {
  mimeType?: string;
  body?: {
    data?: string;
  };
  parts?: GmailMessagePart[];
  headers?: Array<{ name: string; value: string }>;
}

export interface GmailMessage {
  id: string;
  threadId?: string;
  internalDate?: string;
  payload?: GmailMessagePart;
}

/**
 * Strips script/style blocks, HTML tags, and decodes basic entities.
 */
export function htmlToText(html: string): string {
  if (!html) return "";

  let text = html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|tr|h[1-6]|li)>/gi, "\n")
    .replace(/<[^>]+>/g, " ");

  text = text
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, code) => String.fromCharCode(parseInt(code, 16)));

  return text
    .split("\n")
    .map((line) => line.replace(/[^\S\r\n]+/g, " ").trim())
    .filter((line, i, arr) => line.length > 0 || (i > 0 && arr[i - 1].length > 0))
    .join("\n")
    .trim();
}

/**
 * Parses sender display name from From header, or falls back to domain.
 */
export function parseSender(fromHeader?: string): string {
  if (!fromHeader || !fromHeader.trim()) return "unknown";

  const angleMatch = fromHeader.match(/^(.*?)\s*<([^>]+)>/);
  if (angleMatch) {
    let displayName = angleMatch[1].trim();
    if (displayName.startsWith('"') && displayName.endsWith('"')) {
      displayName = displayName.slice(1, -1).trim();
    }
    if (displayName.startsWith("'") && displayName.endsWith("'")) {
      displayName = displayName.slice(1, -1).trim();
    }
    if (displayName.length > 0) {
      return displayName;
    }
    const email = angleMatch[2].trim();
    const atIndex = email.indexOf("@");
    if (atIndex !== -1) {
      return email.slice(atIndex + 1);
    }
    return email;
  }

  const atIndex = fromHeader.indexOf("@");
  if (atIndex !== -1) {
    return fromHeader.slice(atIndex + 1).trim();
  }

  return fromHeader.trim();
}

/**
 * Recursively extracts plain text or converted HTML body from multipart payload.
 */
export function extractBodyFromPayload(payload?: GmailMessagePart): string {
  if (!payload) return "";

  function collect(part?: GmailMessagePart): { plain?: string; html?: string } {
    if (!part) return {};
    let plain: string | undefined;
    let html: string | undefined;

    if (part.mimeType === "text/plain" && part.body?.data) {
      plain = Buffer.from(part.body.data, "base64url").toString("utf8");
    } else if (part.mimeType === "text/html" && part.body?.data) {
      html = Buffer.from(part.body.data, "base64url").toString("utf8");
    }

    if (part.parts && part.parts.length > 0) {
      for (const sub of part.parts) {
        const res = collect(sub);
        if (!plain && res.plain) plain = res.plain;
        if (!html && res.html) html = res.html;
      }
    }

    return { plain, html };
  }

  const { plain, html } = collect(payload);
  if (plain && plain.trim().length > 0) {
    return plain;
  }
  if (html && html.trim().length > 0) {
    return htmlToText(html);
  }
  return "";
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true }
    );
  });
}

/**
 * Polls Gmail for incoming OTP emails for a given account.
 */
export async function watchAccount(options: WatchAccountOptions): Promise<void> {
  const {
    accountId,
    onOtp,
    onError,
    pollMs = 3000,
    signal,
    fetchImpl = globalThis.fetch,
    homeDir = getHomeDir(),
    credentials,
    initialBackoffMs = 3000,
    maxBackoffMs = 60000
  } = options;

  let cachedToken: string | null = null;
  let tokenExpiresAt = 0;

  async function getAccessToken(): Promise<string> {
    const now = Date.now();
    if (cachedToken && now < tokenExpiresAt) {
      return cachedToken;
    }
    const res = await refreshAccessToken(accountId, {
      fetchImpl,
      homeDir,
      credentials
    });
    cachedToken = res.accessToken;
    // Cache until 60 seconds before expiry
    tokenExpiresAt = now + Math.max(0, res.expiresIn * 1000 - 60000);
    return cachedToken;
  }

  // Bounded seen-set of the last 200 message IDs
  const seenSet = new Set<string>();
  const seenQueue: string[] = [];

  function markSeen(id: string): void {
    if (seenSet.has(id)) return;
    if (seenQueue.length >= 200) {
      const oldest = seenQueue.shift();
      if (oldest) seenSet.delete(oldest);
    }
    seenQueue.push(id);
    seenSet.add(id);
  }

  let backoffMs = initialBackoffMs;
  // Start the first window at now minus 60s (epoch seconds of lastPoll - 30s = now - 60s)
  let lastSuccessfulPollEpoch = Math.floor(Date.now() / 1000) - 30;

  while (!signal?.aborted) {
    try {
      const token = await getAccessToken();
      if (signal?.aborted) break;

      const afterSec = lastSuccessfulPollEpoch - 30;
      const q = `in:inbox after:${afterSec}`;
      const listUrl = `https://gmail.googleapis.com/gmail/v1/users/me/messages?q=${encodeURIComponent(
        q
      )}&maxResults=10`;

      const listSignal = signal
        ? AbortSignal.any([signal, AbortSignal.timeout(10000)])
        : AbortSignal.timeout(10000);

      const listRes = await fetchImpl(listUrl, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
        signal: listSignal
      });

      if (listRes.status === 401) {
        cachedToken = null;
        continue;
      }

      if (listRes.status === 429 || (listRes.status >= 500 && listRes.status < 600)) {
        const err = new Error(`Gmail API error: HTTP ${listRes.status}`);
        try {
          await onError?.(err);
        } catch {}
        await sleep(backoffMs, signal);
        backoffMs = Math.min(backoffMs * 2, maxBackoffMs);
        continue;
      }

      if (!listRes.ok) {
        const err = new Error(`Gmail API messages list failed with HTTP ${listRes.status}`);
        try {
          await onError?.(err);
        } catch {}
        await sleep(pollMs, signal);
        continue;
      }

      // Success: reset backoff
      backoffMs = initialBackoffMs;
      lastSuccessfulPollEpoch = Math.floor(Date.now() / 1000);

      const listData = (await listRes.json()) as { messages?: Array<{ id: string }> };
      const messages = listData.messages ?? [];

      for (const msg of messages) {
        if (signal?.aborted) break;
        if (!msg.id || seenSet.has(msg.id)) continue;

        const getSignal = signal
          ? AbortSignal.any([signal, AbortSignal.timeout(10000)])
          : AbortSignal.timeout(10000);

        const msgRes = await fetchImpl(
          `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`,
          {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` },
            signal: getSignal
          }
        );

        if (msgRes.status === 401) {
          cachedToken = null;
          break;
        }

        if (msgRes.status === 429 || (msgRes.status >= 500 && msgRes.status < 600)) {
          const err = new Error(`Gmail API error: HTTP ${msgRes.status}`);
          try {
            await onError?.(err);
          } catch {}
          await sleep(backoffMs, signal);
          backoffMs = Math.min(backoffMs * 2, maxBackoffMs);
          break;
        }

        if (!msgRes.ok) {
          markSeen(msg.id);
          continue;
        }

        markSeen(msg.id);

        const msgData = (await msgRes.json()) as GmailMessage;
        const headers = msgData.payload?.headers ?? [];

        let subject = "";
        let from = "";
        for (const h of headers) {
          const name = h.name.toLowerCase();
          if (name === "subject") subject = h.value;
          if (name === "from") from = h.value;
        }

        const sender = parseSender(from);
        const body = extractBodyFromPayload(msgData.payload);
        const receivedAt = msgData.internalDate ? Number(msgData.internalDate) : Date.now();

        const otp = extractOtp({ subject, body });
        if (otp) {
          try {
            await onOtp({
              accountId,
              sender,
              code: otp.code,
              raw: otp.raw,
              confidence: otp.confidence,
              receivedAt
            });
          } catch (callbackErr) {
            try {
              await onError?.(
                callbackErr instanceof Error ? callbackErr : new Error(String(callbackErr))
              );
            } catch {}
          }
        }
      }

      await sleep(pollMs, signal);
    } catch (err: unknown) {
      if (signal?.aborted) break;

      const error = err instanceof Error ? err : new Error(String(err));
      if (error instanceof ReauthRequiredError || error.name === "ReauthRequiredError") {
        try {
          await onError?.(error);
        } catch {}
        return; // Stop ONLY this account's loop
      }

      try {
        await onError?.(error);
      } catch {}
      await sleep(pollMs, signal);
    }
  }
}
