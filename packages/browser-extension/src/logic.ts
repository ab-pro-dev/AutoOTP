export const MIN_BACKOFF_MS = 1000;
export const MAX_BACKOFF_MS = 30000;
export const OTP_MAX_AGE_MS = 10 * 60 * 1000; // 10 minutes (600,000 ms)

/**
 * Calculates exponential backoff in milliseconds:
 * Starts at 1000ms (1s) and doubles up to 30000ms (30s).
 */
export function calculateBackoff(
  attempt: number,
  minMs = MIN_BACKOFF_MS,
  maxMs = MAX_BACKOFF_MS
): number {
  if (attempt <= 0) return minMs;
  const backoff = minMs * Math.pow(2, attempt);
  return Math.min(backoff, maxMs);
}

/**
 * Doubles current backoff up to maxMs.
 */
export function getNextBackoff(
  currentMs: number,
  maxMs = MAX_BACKOFF_MS
): number {
  if (currentMs <= 0) return MIN_BACKOFF_MS;
  return Math.min(currentMs * 2, maxMs);
}

export interface HelloMessage {
  type: "hello";
  version?: number;
}

export interface PingMessage {
  type: "ping";
}

export interface OtpMessage {
  type: "otp";
  id?: string;
  sender: string;
  senderDomain: string | null;
  code: string;
  account: string;
  receivedAt: number;
  raw?: string;
}

export type ValidatedMessage = HelloMessage | PingMessage | OtpMessage;

/**
 * Validates incoming WebSocket message shapes.
 * Returns the typed message if valid; null if unknown type or malformed.
 */
export function parseIncomingMessage(data: unknown): ValidatedMessage | null {
  let parsed: unknown = data;
  if (typeof data === "string") {
    try {
      parsed = JSON.parse(data);
    } catch {
      return null;
    }
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const obj = parsed as Record<string, unknown>;
  const type = obj.type;

  if (typeof type !== "string") {
    return null;
  }

  if (type === "hello") {
    if (obj.version !== undefined && typeof obj.version !== "number") {
      return null;
    }
    return {
      type: "hello",
      version: obj.version as number | undefined
    };
  }

  if (type === "ping") {
    return { type: "ping" };
  }

  if (type === "otp") {
    const sender = obj.sender;
    const code = obj.code;
    const account = obj.account;
    const receivedAt = obj.receivedAt;

    if (
      typeof sender !== "string" ||
      sender.trim().length === 0 ||
      typeof code !== "string" ||
      code.trim().length === 0 ||
      typeof account !== "string" ||
      account.trim().length === 0 ||
      typeof receivedAt !== "number" ||
      !Number.isFinite(receivedAt)
    ) {
      return null;
    }

    let senderDomain: string | null = null;
    if (typeof obj.senderDomain === "string") {
      const trimmed = obj.senderDomain.trim().toLowerCase();
      if (
        trimmed.length > 0 &&
        trimmed.includes(".") &&
        /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(trimmed)
      ) {
        senderDomain = trimmed;
      }
    }

    return {
      type: "otp",
      id: typeof obj.id === "string" ? obj.id : undefined,
      sender,
      senderDomain,
      code,
      account,
      receivedAt,
      raw: typeof obj.raw === "string" ? obj.raw : undefined
    };
  }

  // Unknown message type
  return null;
}

export type ConnectionStatus =
  | "not_paired"
  | "connecting"
  | "connected"
  | "token_rejected"
  | "service_not_running";

export interface StatusState {
  hasToken: boolean;
  isConnected: boolean;
  isConnecting: boolean;
  tokenRejected: boolean;
}

/**
 * Derives the active connection status given state flags.
 */
export function deriveStatus(state: StatusState): ConnectionStatus {
  if (!state.hasToken) {
    return "not_paired";
  }
  if (state.tokenRejected) {
    return "token_rejected";
  }
  if (state.isConnected) {
    return "connected";
  }
  if (state.isConnecting) {
    return "connecting";
  }
  return "service_not_running";
}

/**
 * Formats a connection status into its user-facing label:
 * Not paired / Connecting / Connected / Token rejected / Service not running
 */
export function formatStatusLabel(status: ConnectionStatus): string {
  switch (status) {
    case "not_paired":
      return "Not paired";
    case "connecting":
      return "Connecting";
    case "connected":
      return "Connected";
    case "token_rejected":
      return "Token rejected";
    case "service_not_running":
      return "Service not running";
  }
}

/**
 * Checks if receivedAt is within the past 10 minutes.
 */
export function isOtpUnderTenMinutes(
  receivedAt: number,
  now = Date.now()
): boolean {
  if (typeof receivedAt !== "number" || !Number.isFinite(receivedAt)) {
    return false;
  }
  const age = now - receivedAt;
  return age >= 0 && age < OTP_MAX_AGE_MS;
}

/**
 * Formats OTP age into human-readable string (e.g. "45s ago", "2m ago").
 */
export function formatOtpAge(receivedAt: number, now = Date.now()): string {
  const diffMs = Math.max(0, now - receivedAt);
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) {
    return `${diffSec}s ago`;
  }
  const diffMin = Math.floor(diffSec / 60);
  return `${diffMin}m ago`;
}

/**
 * Formats OTP display string: "<sender> <code> <age>"
 */
export function formatOtpDisplay(
  otp: { sender: string; code: string; receivedAt: number },
  now = Date.now()
): string {
  const age = formatOtpAge(otp.receivedAt, now);
  return `${otp.sender} ${otp.code} ${age}`;
}

/**
 * Built-in approximation of the Public Suffix List (PSL).
 * Contains common two-part ccTLDs and hosting platforms where subdomains
 * represent distinct and unrelated sites.
 */
export const MULTI_PART_PUBLIC_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "com.au",
  "net.au",
  "co.jp",
  "co.in",
  "co.za",
  "com.br",
  "com.et",
  "gov.et",
  "edu.et",
  "github.io",
  "vercel.app",
  "netlify.app",
  "pages.dev",
  "herokuapp.com",
  "blogspot.com",
  "web.app",
  "firebaseapp.com"
]);

function isIpAddressOrLocalhost(host: string): boolean {
  if (host === "localhost" || host.endsWith(".localhost")) {
    return true;
  }
  // IPv4: 4 numeric octets separated by dots
  const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(host)) {
    return true;
  }
  // IPv6: contains colon (e.g. ::1, fe80::1)
  if (host.includes(":")) {
    return true;
  }
  return false;
}

/**
 * Extracts the registrable domain from a hostname:
 * The last 2 labels, or the last 3 labels if the last 2 form a known multi-part public suffix.
 * Returns null for IP addresses, localhost, empty input, or single-label hostnames.
 */
export function getRegistrableDomain(hostname: string | null | undefined): string | null {
  if (!hostname || typeof hostname !== "string") {
    return null;
  }

  const clean = hostname.trim().toLowerCase();
  if (!clean || isIpAddressOrLocalhost(clean)) {
    return null;
  }

  const labels = clean.split(".");
  if (labels.length < 2 || labels.some((l) => l.length === 0)) {
    return null;
  }

  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_PUBLIC_SUFFIXES.has(lastTwo)) {
    if (labels.length < 3) {
      return null;
    }
    return labels.slice(-3).join(".");
  }

  return labels.slice(-2).join(".");
}

/**
 * Compares two hostnames/domains by their registrable domains.
 * Returns true only if both registrable domains are valid and exactly equal.
 */
export function domainsMatch(
  senderDomain: string | null | undefined,
  pageHostname: string | null | undefined
): boolean {
  if (
    !senderDomain ||
    !pageHostname ||
    typeof senderDomain !== "string" ||
    typeof pageHostname !== "string"
  ) {
    return false;
  }

  const regSender = getRegistrableDomain(senderDomain);
  const regPage = getRegistrableDomain(pageHostname);

  if (!regSender || !regPage) {
    return false;
  }

  return regSender === regPage;
}

