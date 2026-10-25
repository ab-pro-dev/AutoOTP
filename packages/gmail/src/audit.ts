import { extractOtp, containsKeyword } from "@autootp/otp-parser";
import { getHomeDir } from "@autootp/shared";
import { OAuthCredentials, loadCredentials } from "./credentials.js";
import { refreshAccessToken } from "./login.js";
import {
  parseSender,
  parseSenderDomain,
  extractBodyFromPayload,
  isSenderVerified,
  sleep,
  GmailMessage
} from "./watcher.js";

export interface AuditMessageItem {
  id: string;
  sender: string;
  senderDomain: string | null;
  senderVerified: boolean;
  subject: string;
  isDetected: boolean;
  detectedCode?: string;
  detectedRaw?: string;
  confidence?: "high" | "medium";
  isPossibleMiss: boolean;
  isPossibleFalsePositive: boolean;
}

export interface AccountAuditResult {
  accountId: string;
  messages: AuditMessageItem[];
}

export interface AuditAccountOptions {
  accountId: string;
  days: number;
  homeDir?: string;
  fetchImpl?: typeof fetch;
  credentials?: OAuthCredentials;
  initialBackoffMs?: number;
  maxBackoffMs?: number;
  sleepFn?: (ms: number) => Promise<void>;
  signal?: AbortSignal;
}

/**
 * Audits an account's recent INBOX emails for OTP detection calibration.
 * Requests messages up to 200 IDs and fetches each with concurrency <= 4 and 429/5xx backoff.
 */
export async function auditAccount(options: AuditAccountOptions): Promise<AccountAuditResult> {
  const {
    accountId,
    days,
    homeDir = getHomeDir(),
    fetchImpl = globalThis.fetch,
    credentials,
    initialBackoffMs = 1000,
    maxBackoffMs = 16000,
    sleepFn = sleep,
    signal
  } = options;

  const { accessToken } = await refreshAccessToken(accountId, {
    fetchImpl,
    homeDir,
    credentials
  });

  const messageIds: string[] = [];
  let pageToken: string | undefined = undefined;

  // 1. List messages up to 200 IDs with backoff on 429/5xx
  do {
    if (signal?.aborted) break;

    let url = `https://gmail.googleapis.com/gmail/v1/users/me/messages?labelIds=INBOX&q=${encodeURIComponent(`newer_than:${days}d`)}&maxResults=100`;
    if (pageToken) {
      url += `&pageToken=${encodeURIComponent(pageToken)}`;
    }

    let attempt = 0;
    let backoff = initialBackoffMs;
    let listData: { messages?: Array<{ id: string }>; nextPageToken?: string } | null = null;

    while (attempt < 5) {
      if (signal?.aborted) break;
      attempt++;
      let res: Response;
      try {
        res = await fetchImpl(url, {
          method: "GET",
          headers: { Authorization: `Bearer ${accessToken}` },
          signal
        });
      } catch {
        if (attempt >= 5) break;
        await sleepFn(backoff);
        backoff = Math.min(backoff * 2, maxBackoffMs);
        continue;
      }

      if (res.status === 429 || (res.status >= 500 && res.status < 600)) {
        if (attempt >= 5) break;
        await sleepFn(backoff);
        backoff = Math.min(backoff * 2, maxBackoffMs);
        continue;
      }

      if (!res.ok) {
        break;
      }

      listData = (await res.json()) as { messages?: Array<{ id: string }>; nextPageToken?: string };
      break;
    }

    if (!listData) break;

    for (const m of listData.messages ?? []) {
      if (m.id && messageIds.length < 200) {
        messageIds.push(m.id);
      }
    }

    pageToken = listData.nextPageToken;
  } while (pageToken && messageIds.length < 200);

  // 2. Fetch each message with concurrency <= 4 and backoff on 429/5xx
  const CONCURRENCY = 4;
  const results: (AuditMessageItem | null)[] = new Array(messageIds.length);
  let nextIdx = 0;

  const workers = Array.from({ length: Math.min(CONCURRENCY, messageIds.length) }, async () => {
    while (nextIdx < messageIds.length) {
      if (signal?.aborted) break;
      const idx = nextIdx++;
      const msgId = messageIds[idx];

      let attempt = 0;
      let backoff = initialBackoffMs;
      let msgData: GmailMessage | null = null;

      while (attempt < 5) {
        if (signal?.aborted) break;
        attempt++;
        let res: Response;
        try {
          res = await fetchImpl(
            `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msgId}?format=full`,
            {
              method: "GET",
              headers: { Authorization: `Bearer ${accessToken}` },
              signal
            }
          );
        } catch {
          if (attempt >= 5) break;
          await sleepFn(backoff);
          backoff = Math.min(backoff * 2, maxBackoffMs);
          continue;
        }

        if (res.status === 429 || (res.status >= 500 && res.status < 600)) {
          if (attempt >= 5) break;
          await sleepFn(backoff);
          backoff = Math.min(backoff * 2, maxBackoffMs);
          continue;
        }

        if (!res.ok) {
          break;
        }

        msgData = (await res.json()) as GmailMessage;
        break;
      }

      if (!msgData) continue;

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
      const senderVerified = isSenderVerified(headers, senderDomain);
      const body = extractBodyFromPayload(msgData.payload);

      const otp = extractOtp({ subject, body });
      const isDetected = otp !== null;

      const isPossibleMiss =
        !isDetected && (containsKeyword(subject) || containsKeyword(body.slice(0, 300)));

      let isPossibleFalsePositive = false;
      if (isDetected && otp) {
        if (otp.confidence === "medium") {
          isPossibleFalsePositive = true;
        } else {
          const subjectHasKw = containsKeyword(subject);
          let beforeCodeHasKw = false;
          if (otp.raw) {
            const codeIdx = body.indexOf(otp.raw);
            if (codeIdx !== -1) {
              const sliceBefore = body.slice(Math.max(0, codeIdx - 80), codeIdx);
              beforeCodeHasKw = containsKeyword(sliceBefore);
            }
          }
          if (!subjectHasKw && !beforeCodeHasKw) {
            isPossibleFalsePositive = true;
          }
        }
      }

      results[idx] = {
        id: msgId,
        sender,
        senderDomain,
        senderVerified,
        subject,
        isDetected,
        detectedCode: otp?.code,
        detectedRaw: otp?.raw,
        confidence: otp?.confidence,
        isPossibleMiss,
        isPossibleFalsePositive
      };
    }
  });

  await Promise.all(workers);

  return {
    accountId,
    messages: results.filter((m): m is AuditMessageItem => m !== null)
  };
}
