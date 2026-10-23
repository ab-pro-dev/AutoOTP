import { extractOtp } from "@autootp/otp-parser";
import { getHomeDir } from "@autootp/shared";
import { OAuthCredentials } from "./credentials.js";
import { refreshAccessToken } from "./login.js";
import { ReauthRequiredError } from "./errors.js";

export interface OtpNotification {
  id?: string;
  messageId?: string;
  accountId: string;
  sender: string;
  senderDomain?: string | null;
  code: string;
  raw: string;
  confidence: "high" | "medium";
  receivedAt: number;
}

export interface WatchAccountOptions {
  accountId: string;
  onOtp: (otp: OtpNotification) => void | Promise<void>;
  onError?: (err: Error) => void | Promise<void>;
  onPollSuccess?: (accountId: string) => void | Promise<void>;
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
 * Extracts the sender's host/domain from a From header:
 * - Extracts address from "Name <user@host>" or a bare "user@host"
 * - Lowercases the host
 * - Accepts only /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/ with at least one dot
 * - Anything else returns null
 */
export function parseSenderDomain(fromHeader?: string): string | null {
  if (!fromHeader || typeof fromHeader !== "string") {
    return null;
  }

  const angleMatch = fromHeader.match(/<([^>]+)>/);
  const addr = (angleMatch ? angleMatch[1] : fromHeader).trim();
  const atIndex = addr.lastIndexOf("@");
  if (atIndex === -1 || atIndex === 0 || atIndex === addr.length - 1) {
    return null;
  }

  const host = addr.slice(atIndex + 1).trim().toLowerCase();
  if (!host.includes(".")) {
    return null;
  }

  const domainRegex = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/;
  if (!domainRegex.test(host)) {
    return null;
  }

  return host;
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
    } else if (!part.mimeType && part.body?.data) {
      plain = Buffer.from(part.body.data, "base64url").toString("utf8");
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

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    let timer: NodeJS.Timeout | undefined;

    const cleanup = () => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      signal?.removeEventListener("abort", onAbort);
    };

    const onAbort = () => {
      cleanup();
      resolve();
    };

    timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);

    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch,
  timeoutMs: number = 10000,
  signal?: AbortSignal
): Promise<Response> {
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;

  const onAbort = () => {
    controller.abort(signal?.reason);
  };

  if (signal) {
    if (signal.aborted) {
      controller.abort(signal.reason);
    } else {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  }

  timer = setTimeout(() => {
    timer = undefined;
    controller.abort(new DOMException("The operation was aborted due to timeout", "TimeoutError"));
  }, timeoutMs);

  try {
    return await fetchImpl(url, {
      ...init,
      signal: controller.signal
    });
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
    if (signal) {
      signal.removeEventListener("abort", onAbort);
    }
  }
}


/**
 * Polls Gmail for incoming OTP emails for a given account using Gmail history API.
 */
export async function watchAccount(options: WatchAccountOptions): Promise<void> {
  const {
    accountId,
    onOtp,
    onError,
    onPollSuccess,
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
  let startHistoryId: string | null = null;

  async function processMessage(
    msgId: string,
    token: string,
    maxAgeMs?: number
  ): Promise<boolean> {
    const msgRes = await fetchWithTimeout(
      `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msgId}?format=full`,
      {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` }
      },
      fetchImpl,
      10000,
      signal
    );

    if (msgRes.status === 401) {
      cachedToken = null;
      return false;
    }

    if (msgRes.status === 429 || (msgRes.status >= 500 && msgRes.status < 600)) {
      const err = new Error(`Gmail API error: HTTP ${msgRes.status}`);
      try {
        await onError?.(err);
      } catch {}
      await sleep(backoffMs, signal);
      backoffMs = Math.min(backoffMs * 2, maxBackoffMs);
      return false;
    }

    if (!msgRes.ok) {
      markSeen(msgId);
      return true;
    }

    markSeen(msgId);

    const msgData = (await msgRes.json()) as GmailMessage;
    const receivedAt = msgData.internalDate ? Number(msgData.internalDate) : Date.now();

    if (maxAgeMs !== undefined) {
      if (Date.now() - receivedAt > maxAgeMs) {
        return true;
      }
    }

    const headers = msgData.payload?.headers ?? [];
    let subject = "";
    let from = "";
    for (const h of headers) {
      const name = h.name.toLowerCase();
      if (name === "subject") subject = h.value;
      if (name === "from") from = h.value;
    }

    const sender = parseSender(from);
    const senderDomain = parseSenderDomain(from);
    const body = extractBodyFromPayload(msgData.payload);

    const otp = extractOtp({ subject, body });
    if (otp) {
      if (process.env.AUTOOTP_DEBUG === "timing") {
        const detected = Date.now();
        const latency = Math.max(0, detected - receivedAt);
        console.error(`latency: ${latency} ms (received to detected)`);
      }

      try {
        await onOtp({
          id: msgId,
          messageId: msgId,
          accountId,
          sender,
          senderDomain,
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

    return true;
  }

  async function fetchHistoryId(token: string): Promise<string | null> {
    const profileRes = await fetchWithTimeout(
      "https://gmail.googleapis.com/gmail/v1/users/me/profile",
      {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` }
      },
      fetchImpl,
      10000,
      signal
    );

    if (profileRes.status === 401) {
      cachedToken = null;
      return null;
    }

    if (profileRes.status === 429 || (profileRes.status >= 500 && profileRes.status < 600)) {
      const err = new Error(`Gmail API error: HTTP ${profileRes.status}`);
      try {
        await onError?.(err);
      } catch {}
      await sleep(backoffMs, signal);
      backoffMs = Math.min(backoffMs * 2, maxBackoffMs);
      return null;
    }

    if (!profileRes.ok) {
      const err = new Error(`Gmail API getProfile failed with HTTP ${profileRes.status}`);
      try {
        await onError?.(err);
      } catch {}
      return null;
    }

    const profileData = (await profileRes.json()) as { historyId?: string | number };
    return profileData.historyId ? String(profileData.historyId) : null;
  }

  async function runRecoveryList(token: string): Promise<boolean> {
    const listRes = await fetchWithTimeout(
      "https://gmail.googleapis.com/gmail/v1/users/me/messages?labelIds=INBOX&maxResults=10",
      {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` }
      },
      fetchImpl,
      10000,
      signal
    );

    if (listRes.status === 401) {
      cachedToken = null;
      return false;
    }

    if (listRes.status === 429 || (listRes.status >= 500 && listRes.status < 600)) {
      const err = new Error(`Gmail API error: HTTP ${listRes.status}`);
      try {
        await onError?.(err);
      } catch {}
      await sleep(backoffMs, signal);
      backoffMs = Math.min(backoffMs * 2, maxBackoffMs);
      return false;
    }

    if (!listRes.ok) {
      const err = new Error(`Gmail API messages list failed with HTTP ${listRes.status}`);
      try {
        await onError?.(err);
      } catch {}
      return false;
    }

    const listData = (await listRes.json()) as { messages?: Array<{ id: string }> };
    const messages = listData.messages ?? [];

    for (const msg of messages) {
      if (signal?.aborted) break;
      if (!msg.id || seenSet.has(msg.id)) continue;
      await processMessage(msg.id, token, 60000);
    }

    return true;
  }

  while (!signal?.aborted) {
    try {
      const token = await getAccessToken();
      if (signal?.aborted) break;

      // Start / initial setup
      if (!startHistoryId) {
        const initialHistoryId = await fetchHistoryId(token);
        if (!initialHistoryId) {
          await sleep(pollMs, signal);
          continue;
        }
        startHistoryId = initialHistoryId;
        await runRecoveryList(token);
        backoffMs = initialBackoffMs;
        try {
          await onPollSuccess?.(accountId);
        } catch {}
        await sleep(pollMs, signal);
        continue;
      }

      // History polling
      let pageToken: string | undefined = undefined;
      let nextStartHistoryId: string | null = null;
      const addedMessageIds: string[] = [];
      let had404 = false;
      let hadAuthOrRateError = false;

      do {
        if (signal?.aborted) break;

        let historyUrl = `https://gmail.googleapis.com/gmail/v1/users/me/history?startHistoryId=${startHistoryId}&historyTypes=messageAdded&labelId=INBOX`;
        if (pageToken) {
          historyUrl += `&pageToken=${encodeURIComponent(pageToken)}`;
        }

        const historyRes = await fetchWithTimeout(
          historyUrl,
          {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` }
          },
          fetchImpl,
          10000,
          signal
        );

        if (historyRes.status === 401) {
          cachedToken = null;
          hadAuthOrRateError = true;
          break;
        }

        if (historyRes.status === 404) {
          had404 = true;
          break;
        }

        if (historyRes.status === 429 || (historyRes.status >= 500 && historyRes.status < 600)) {
          const err = new Error(`Gmail API error: HTTP ${historyRes.status}`);
          try {
            await onError?.(err);
          } catch {}
          await sleep(backoffMs, signal);
          backoffMs = Math.min(backoffMs * 2, maxBackoffMs);
          hadAuthOrRateError = true;
          break;
        }

        if (!historyRes.ok) {
          const err = new Error(`Gmail API history failed with HTTP ${historyRes.status}`);
          try {
            await onError?.(err);
          } catch {}
          hadAuthOrRateError = true;
          break;
        }

        const historyData = (await historyRes.json()) as {
          history?: Array<{
            messagesAdded?: Array<{ message?: { id?: string }; id?: string }>;
            messages?: Array<{ id?: string }>;
          }>;
          historyId?: string | number;
          nextPageToken?: string;
        };

        if (historyData.historyId) {
          nextStartHistoryId = String(historyData.historyId);
        }

        const historyList = historyData.history ?? [];
        for (const record of historyList) {
          if (record.messagesAdded) {
            for (const entry of record.messagesAdded) {
              const id = entry.message?.id ?? entry.id;
              if (id && !seenSet.has(id) && !addedMessageIds.includes(id)) {
                addedMessageIds.push(id);
              }
            }
          } else if (record.messages) {
            for (const msg of record.messages) {
              if (msg.id && !seenSet.has(msg.id) && !addedMessageIds.includes(msg.id)) {
                addedMessageIds.push(msg.id);
              }
            }
          }
        }

        pageToken = historyData.nextPageToken;
      } while (pageToken && !signal?.aborted);

      if (had404) {
        // Expired history: re-run getProfile and 60-second recovery list
        const recoveredHistoryId = await fetchHistoryId(token);
        if (recoveredHistoryId) {
          startHistoryId = recoveredHistoryId;
        }
        await runRecoveryList(token);
        backoffMs = initialBackoffMs;
        try {
          await onPollSuccess?.(accountId);
        } catch {}
        await sleep(pollMs, signal);
        continue;
      }

      if (hadAuthOrRateError) {
        continue;
      }

      // Store top-level historyId as new startHistoryId
      if (nextStartHistoryId) {
        startHistoryId = nextStartHistoryId;
      }
      backoffMs = initialBackoffMs;

      for (const msgId of addedMessageIds) {
        if (signal?.aborted) break;
        if (seenSet.has(msgId)) continue;
        await processMessage(msgId, token);
      }

      try {
        await onPollSuccess?.(accountId);
      } catch {}

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
