import { describe, it, expect } from "vitest";
import {
  calculateBackoff,
  getNextBackoff,
  parseIncomingMessage,
  deriveStatus,
  formatStatusLabel,
  isOtpUnderTenMinutes,
  formatOtpAge,
  formatOtpDisplay,
  MIN_BACKOFF_MS,
  MAX_BACKOFF_MS,
  OTP_MAX_AGE_MS
} from "./logic.js";

describe("Backoff Calculation", () => {
  it("calculates exponential backoff starting at 1000ms and capping at 30000ms", () => {
    expect(calculateBackoff(0)).toBe(1000);
    expect(calculateBackoff(1)).toBe(2000);
    expect(calculateBackoff(2)).toBe(4000);
    expect(calculateBackoff(3)).toBe(8000);
    expect(calculateBackoff(4)).toBe(16000);
    expect(calculateBackoff(5)).toBe(30000); // capped
    expect(calculateBackoff(6)).toBe(30000);
    expect(calculateBackoff(10)).toBe(30000);
  });

  it("handles negative or zero attempt", () => {
    expect(calculateBackoff(-1)).toBe(1000);
    expect(calculateBackoff(0)).toBe(1000);
  });

  it("getNextBackoff doubles current value up to 30000ms", () => {
    expect(getNextBackoff(0)).toBe(MIN_BACKOFF_MS);
    expect(getNextBackoff(1000)).toBe(2000);
    expect(getNextBackoff(2000)).toBe(4000);
    expect(getNextBackoff(8000)).toBe(16000);
    expect(getNextBackoff(16000)).toBe(30000);
    expect(getNextBackoff(30000)).toBe(30000);
    expect(getNextBackoff(40000)).toBe(30000);
  });
});

describe("Incoming Message Validation", () => {
  it("validates valid hello messages", () => {
    const raw = JSON.stringify({ type: "hello", version: 1 });
    const msg = parseIncomingMessage(raw);
    expect(msg).toEqual({ type: "hello", version: 1 });

    const msgObj = parseIncomingMessage({ type: "hello" });
    expect(msgObj).toEqual({ type: "hello", version: undefined });
  });

  it("validates valid ping messages", () => {
    const raw = JSON.stringify({ type: "ping" });
    expect(parseIncomingMessage(raw)).toEqual({ type: "ping" });
  });

  it("validates valid otp messages", () => {
    const otpPayload = {
      type: "otp",
      id: "msg-123",
      sender: "GitHub",
      code: "892147",
      account: "personal",
      receivedAt: 1700000000000,
      raw: "Your code is 892147"
    };

    const msg = parseIncomingMessage(JSON.stringify(otpPayload));
    expect(msg).toEqual(otpPayload);
  });

  it("rejects malformed inputs and non-objects", () => {
    expect(parseIncomingMessage("invalid json {")).toBeNull();
    expect(parseIncomingMessage(null)).toBeNull();
    expect(parseIncomingMessage(undefined)).toBeNull();
    expect(parseIncomingMessage([])).toBeNull();
    expect(parseIncomingMessage(42)).toBeNull();
    expect(parseIncomingMessage("")).toBeNull();
    expect(parseIncomingMessage({})).toBeNull(); // missing type
    expect(parseIncomingMessage({ type: 123 })).toBeNull();
  });

  it("rejects unknown message types", () => {
    expect(parseIncomingMessage({ type: "unknown" })).toBeNull();
    expect(parseIncomingMessage({ type: "pong" })).toBeNull();
    expect(parseIncomingMessage({ type: "auth" })).toBeNull();
    expect(parseIncomingMessage(JSON.stringify({ type: "something_else" }))).toBeNull();
  });

  it("rejects malformed otp messages with missing or invalid fields", () => {
    // missing sender
    expect(
      parseIncomingMessage({
        type: "otp",
        code: "123456",
        account: "personal",
        receivedAt: 1700000000000
      })
    ).toBeNull();

    // empty sender
    expect(
      parseIncomingMessage({
        type: "otp",
        sender: "   ",
        code: "123456",
        account: "personal",
        receivedAt: 1700000000000
      })
    ).toBeNull();

    // missing code
    expect(
      parseIncomingMessage({
        type: "otp",
        sender: "Google",
        account: "personal",
        receivedAt: 1700000000000
      })
    ).toBeNull();

    // missing account
    expect(
      parseIncomingMessage({
        type: "otp",
        sender: "Google",
        code: "123456",
        receivedAt: 1700000000000
      })
    ).toBeNull();

    // missing receivedAt
    expect(
      parseIncomingMessage({
        type: "otp",
        sender: "Google",
        code: "123456",
        account: "personal"
      })
    ).toBeNull();

    // non-number receivedAt
    expect(
      parseIncomingMessage({
        type: "otp",
        sender: "Google",
        code: "123456",
        account: "personal",
        receivedAt: "1700000000000"
      })
    ).toBeNull();

    // NaN receivedAt
    expect(
      parseIncomingMessage({
        type: "otp",
        sender: "Google",
        code: "123456",
        account: "personal",
        receivedAt: NaN
      })
    ).toBeNull();
  });

  it("rejects hello message with non-number version", () => {
    expect(parseIncomingMessage({ type: "hello", version: "1" })).toBeNull();
  });
});

describe("Status Derivation & Formatting", () => {
  it("derives not_paired when hasToken is false", () => {
    expect(
      deriveStatus({
        hasToken: false,
        isConnected: false,
        isConnecting: false,
        tokenRejected: false
      })
    ).toBe("not_paired");

    // Even if isConnected was somehow true, no token means not paired
    expect(
      deriveStatus({
        hasToken: false,
        isConnected: true,
        isConnecting: false,
        tokenRejected: false
      })
    ).toBe("not_paired");
  });

  it("derives token_rejected when tokenRejected is true and hasToken is true", () => {
    expect(
      deriveStatus({
        hasToken: true,
        isConnected: false,
        isConnecting: false,
        tokenRejected: true
      })
    ).toBe("token_rejected");
  });

  it("derives connected when isConnected is true", () => {
    expect(
      deriveStatus({
        hasToken: true,
        isConnected: true,
        isConnecting: false,
        tokenRejected: false
      })
    ).toBe("connected");
  });

  it("derives connecting when isConnecting is true and not connected", () => {
    expect(
      deriveStatus({
        hasToken: true,
        isConnected: false,
        isConnecting: true,
        tokenRejected: false
      })
    ).toBe("connecting");
  });

  it("derives service_not_running when token exists but disconnected and not rejected", () => {
    expect(
      deriveStatus({
        hasToken: true,
        isConnected: false,
        isConnecting: false,
        tokenRejected: false
      })
    ).toBe("service_not_running");
  });

  it("formats user-facing status labels correctly", () => {
    expect(formatStatusLabel("not_paired")).toBe("Not paired");
    expect(formatStatusLabel("connecting")).toBe("Connecting");
    expect(formatStatusLabel("connected")).toBe("Connected");
    expect(formatStatusLabel("token_rejected")).toBe("Token rejected");
    expect(formatStatusLabel("service_not_running")).toBe("Service not running");
  });
});

describe("OTP 10-Minute Age Check & Display Formatting", () => {
  const now = 1700000600000; // Reference timestamp

  it("accepts OTPs received under 10 minutes ago", () => {
    // 0 seconds ago
    expect(isOtpUnderTenMinutes(now, now)).toBe(true);

    // 30 seconds ago
    expect(isOtpUnderTenMinutes(now - 30 * 1000, now)).toBe(true);

    // 5 minutes ago
    expect(isOtpUnderTenMinutes(now - 5 * 60 * 1000, now)).toBe(true);

    // 9 minutes 59 seconds ago
    expect(isOtpUnderTenMinutes(now - (OTP_MAX_AGE_MS - 1000), now)).toBe(true);
  });

  it("rejects OTPs received 10 or more minutes ago", () => {
    // Exactly 10 minutes ago (600,000 ms)
    expect(isOtpUnderTenMinutes(now - OTP_MAX_AGE_MS, now)).toBe(false);

    // 10 minutes 1 second ago
    expect(isOtpUnderTenMinutes(now - (OTP_MAX_AGE_MS + 1000), now)).toBe(false);

    // 1 hour ago
    expect(isOtpUnderTenMinutes(now - 60 * 60 * 1000, now)).toBe(false);
  });

  it("rejects future timestamps or invalid inputs", () => {
    // Future timestamp
    expect(isOtpUnderTenMinutes(now + 1000, now)).toBe(false);

    // NaN / Infinity / non-numbers
    expect(isOtpUnderTenMinutes(NaN, now)).toBe(false);
    expect(isOtpUnderTenMinutes(Infinity, now)).toBe(false);
    expect(isOtpUnderTenMinutes(null as any, now)).toBe(false);
  });

  it("formats age in seconds and minutes", () => {
    expect(formatOtpAge(now, now)).toBe("0s ago");
    expect(formatOtpAge(now - 5 * 1000, now)).toBe("5s ago");
    expect(formatOtpAge(now - 59 * 1000, now)).toBe("59s ago");
    expect(formatOtpAge(now - 60 * 1000, now)).toBe("1m ago");
    expect(formatOtpAge(now - 90 * 1000, now)).toBe("1m ago");
    expect(formatOtpAge(now - 5 * 60 * 1000, now)).toBe("5m ago");
    expect(formatOtpAge(now - 9 * 60 * 1000, now)).toBe("9m ago");
  });

  it("formats OTP display as '<sender> <code> <age>'", () => {
    const formatted = formatOtpDisplay(
      {
        sender: "GitHub",
        code: "948210",
        receivedAt: now - 45 * 1000
      },
      now
    );
    expect(formatted).toBe("GitHub 948210 45s ago");
  });
});
