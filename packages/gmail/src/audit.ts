import {
  extractOtp,
  containsKeyword,
  scanKeywords,
  getCandidateShape
} from "@autootp/otp-parser";
import { getHomeDir } from "@autootp/shared";
import { OAuthCredentials, loadCredentials } from "./credentials.js";
import { refreshAccessToken } from "./login.js";
import { stripParentheticalComments, HeaderItem } from "./verification.js";
import {
  parseSender,
  parseSenderDomain,
  extractBodyFromPayload,
  isSenderVerified,
  sleep,
  GmailMessage
} from "./watcher.js";

export interface AuditAuthInfo {
  authservId: string | null;
  verdicts: string[];
  headerFrom: string | null;
  headerD: string | null;
  smtpMailfrom: string | null;
}

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
  candidateShape?: string;
  nearestKeyword?: string | null;
  nearestKeywordDistance?: number | null;
  authInfo?: AuditAuthInfo | null;
  contextWindow?: string;
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
 * Parses the first Authentication-Results header to extract verdicts and domains safely.
 */
export function parseAuthResults(headers: HeaderItem[]): AuditAuthInfo | null {
  if (!Array.isArray(headers)) return null;

  const authHeaders = headers.filter(
    (h) => h && typeof h.name === "string" && h.name.toLowerCase() === "authentication-results"
  );
  if (authHeaders.length === 0) return null;

  const rawHeader = authHeaders[0].value;
  if (typeof rawHeader !== "string") return null;

  const { text: cleaned, malformed } = stripParentheticalComments(rawHeader);
  if (malformed || !cleaned.includes(";")) {
    const authservId = cleaned.trim().split(/\s+/)[0] || null;
    return {
      authservId,
      verdicts: [],
      headerFrom: null,
      headerD: null,
      smtpMailfrom: null
    };
  }

  const parts = cleaned.split(";");
  const serverPart = parts[0].trim();
  const serverTokens = serverPart.split(/\s+/).filter(Boolean);
  const authservId = serverTokens.length > 0 ? serverTokens[0] : null;

  const verdicts: string[] = [];
  let headerFrom: string | null = null;
  let headerD: string | null = null;
  let smtpMailfrom: string | null = null;

  for (let i = 1; i < parts.length; i++) {
    const segment = parts[i].trim();
    if (!segment) continue;

    const methodMatch = segment.match(/^([a-zA-Z0-9_.-]+)\s*=\s*([a-zA-Z0-9_.-]+)/);
    if (methodMatch) {
      verdicts.push(`${methodMatch[1].toLowerCase()}=${methodMatch[2].toLowerCase()}`);
    }

    if (!headerFrom) {
      const match = segment.match(/(?:^|\s)header\.from\s*=\s*(?:"([^"]*)"|([^\s;]+))/i);
      if (match) {
        headerFrom = (match[1] || match[2]).toLowerCase();
      }
    }

    if (!headerD) {
      const match = segment.match(/(?:^|\s)header\.d\s*=\s*(?:"([^"]*)"|([^\s;]+))/i);
      if (match) {
        headerD = (match[1] || match[2]).toLowerCase();
      }
    }

    if (!smtpMailfrom) {
      const match = segment.match(/(?:^|\s)smtp\.mailfrom\s*=\s*(?:"([^"]*)"|([^\s;]+))/i);
      if (match) {
        let rawMailfrom = match[1] || match[2];
        rawMailfrom = rawMailfrom.replace(/^[<"]+|[>"]+$/g, "");
        const at = rawMailfrom.lastIndexOf("@");
        smtpMailfrom = (at !== -1 ? rawMailfrom.slice(at + 1) : rawMailfrom).toLowerCase();
      }
    }
  }

  return {
    authservId,
    verdicts,
    headerFrom,
    headerD,
    smtpMailfrom
  };
}

/**
 * Normalizes a snippet for context window: strips markup, control chars, and newlines.
 */
export function cleanContextSnippet(text: string): string {
  if (!text) return "";
  let res = text
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">");
  res = res.replace(/<[^>]*>/g, " ");
  res = res.replace(/[\x00-\x1F\x7F\r\n\t]/g, " ");
  res = res.replace(/\s+/g, " ");
  return res;
}

/**
 * Finds the nearest keyword from KEYWORD_TABLE and its character distance to the candidate.
 */
export function findNearestKeyword(
  body: string,
  subject: string,
  candRaw?: string
): { keyword: string | null; distance: number | null } {
  if (!candRaw) {
    return { keyword: null, distance: null };
  }

  let targetText = body || "";
  let candStart = targetText.indexOf(candRaw);

  if (candStart === -1 && subject) {
    const subjIdx = subject.indexOf(candRaw);
    if (subjIdx !== -1) {
      targetText = subject;
      candStart = subjIdx;
    }
  }

  if (candStart === -1) {
    return { keyword: null, distance: null };
  }

  const candEnd = candStart + candRaw.length;
  const matches = scanKeywords(targetText);

  let bestKeyword: string | null = null;
  let bestDist = Infinity;

  for (const m of matches) {
    const kwStart = m.index;
    const kwEnd = kwStart + m.phrase.length;

    let dist: number;
    if (kwEnd <= candStart) {
      dist = candStart - kwEnd;
    } else if (kwStart >= candEnd) {
      dist = kwStart - candEnd;
    } else {
      dist = 0;
    }

    if (dist < bestDist) {
      bestDist = dist;
      bestKeyword = m.phrase;
    }
  }

  if (bestKeyword !== null && bestDist <= 80) {
    return { keyword: bestKeyword, distance: bestDist };
  }

  return { keyword: null, distance: null };
}

/**
 * Builds a masked context window (<= 40 chars before and after), replacing the candidate with
 * <CODE:<shape>>, runs of 4+ digits with <N>, and stripping email local parts.
 * Never exceeds 100 characters.
 */
export function maskContextWindow(
  bodyText: string,
  subjectText: string,
  candRaw?: string,
  shape: string = "none",
  extraLocalParts: string[] = []
): string {
  let targetText = bodyText || "";
  let idx = candRaw ? targetText.indexOf(candRaw) : -1;

  if (idx === -1 && candRaw && subjectText) {
    const subjIdx = subjectText.indexOf(candRaw);
    if (subjIdx !== -1) {
      targetText = subjectText;
      idx = subjIdx;
    }
  }

  const maskEmailLocalParts = (str: string) => {
    let res = str.replace(/\b[A-Za-z0-9._%+-]+(@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)/g, "***$1");
    for (const lp of extraLocalParts) {
      if (lp && lp.length >= 2) {
        res = res.replaceAll(lp, "***");
      }
    }
    return res;
  };

  const maskOtherDigits = (str: string) => str.replace(/\d{4,}/g, "<N>");

  if (candRaw && idx !== -1) {
    const beforeRaw = targetText.slice(Math.max(0, idx - 40), idx);
    const afterRaw = targetText.slice(
      idx + candRaw.length,
      Math.min(targetText.length, idx + candRaw.length + 40)
    );

    let before = cleanContextSnippet(beforeRaw);
    before = maskEmailLocalParts(before);
    before = maskOtherDigits(before);

    let after = cleanContextSnippet(afterRaw);
    after = maskEmailLocalParts(after);
    after = maskOtherDigits(after);

    const token = `<CODE:${shape}>`;
    let result = `${before}${token}${after}`.trim();
    if (result.length > 100) {
      result = result.slice(0, 100);
    }
    return result;
  }

  // Fallback when no candidate (e.g. possible miss): find nearest keyword in body or subject
  let kwIdx = -1;
  let kwLen = 0;
  const kwMatches = scanKeywords(targetText);
  if (kwMatches.length > 0) {
    kwIdx = kwMatches[0].index;
    kwLen = kwMatches[0].phrase.length;
  } else if (subjectText) {
    const subjMatches = scanKeywords(subjectText);
    if (subjMatches.length > 0) {
      targetText = subjectText;
      kwIdx = subjMatches[0].index;
      kwLen = subjMatches[0].phrase.length;
    }
  }

  if (kwIdx !== -1) {
    const beforeRaw = targetText.slice(Math.max(0, kwIdx - 40), kwIdx);
    const kwText = targetText.slice(kwIdx, kwIdx + kwLen);
    const afterRaw = targetText.slice(
      kwIdx + kwLen,
      Math.min(targetText.length, kwIdx + kwLen + 40)
    );

    let before = cleanContextSnippet(beforeRaw);
    before = maskEmailLocalParts(before);
    before = maskOtherDigits(before);

    let after = cleanContextSnippet(afterRaw);
    after = maskEmailLocalParts(after);
    after = maskOtherDigits(after);

    let result = `${before}${kwText}${after}`.trim();
    if (result.length > 100) {
      result = result.slice(0, 100);
    }
    return result;
  }

  // If no keyword either, take up to 80 chars of body
  let snippet = cleanContextSnippet(targetText.slice(0, 80));
  snippet = maskEmailLocalParts(snippet);
  snippet = maskOtherDigits(snippet);
  if (snippet.length > 100) {
    snippet = snippet.slice(0, 100);
  }
  return snippet || "(no content)";
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

      // Collect known email local parts from headers so they never leak in explain context
      const extraLocalParts: string[] = [];
      const emailMatch = from.match(/<([^>]+)>|([^\s<]+@[^\s>]+)/);
      if (emailMatch) {
        const fullAddr = emailMatch[1] || emailMatch[2];
        const at = fullAddr.indexOf("@");
        if (at !== -1) {
          extraLocalParts.push(fullAddr.slice(0, at));
        }
      }
      for (const h of headers) {
        if (h.name.toLowerCase() === "authentication-results") {
          for (const m of h.value.matchAll(/(?:header\.i|smtp\.mailfrom)=["<]?([^@"<>;\s]+)@/gi)) {
            if (m[1]) extraLocalParts.push(m[1]);
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
        isPossibleFalsePositive,
        candidateShape: getCandidateShape(otp?.raw),
        nearestKeyword: findNearestKeyword(body, subject, otp?.raw).keyword,
        nearestKeywordDistance: findNearestKeyword(body, subject, otp?.raw).distance,
        authInfo: parseAuthResults(headers),
        contextWindow: maskContextWindow(
          body,
          subject,
          otp?.raw,
          getCandidateShape(otp?.raw),
          extraLocalParts
        )
      };
    }
  });

  await Promise.all(workers);

  return {
    accountId,
    messages: results.filter((m): m is AuditMessageItem => m !== null)
  };
}
