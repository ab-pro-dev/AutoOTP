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

    return {
      type: "otp",
      id: typeof obj.id === "string" ? obj.id : undefined,
      sender,
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
