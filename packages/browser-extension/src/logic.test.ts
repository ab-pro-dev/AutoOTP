import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  calculateBackoff,
  getNextBackoff,
  parseIncomingMessage,
  deriveStatus,
  formatStatusLabel,
  isOtpUnderTenMinutes,
  formatOtpAge,
  formatOtpDisplay,
  getRegistrableDomain,
  domainsMatch,
  MULTI_PART_PUBLIC_SUFFIXES,
  MIN_BACKOFF_MS,
  MAX_BACKOFF_MS,
  OTP_MAX_AGE_MS,
  decideAutofill,
  scoreField,
  groupSegmented,
  validateFieldsMessage,
  validateFillMessage,
  FieldDescriptor,
  deriveViewState,
  formatUsedFeedback
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

  it("validates valid otp messages with and without senderDomain", () => {
    const otpPayloadWithDomain = {
      type: "otp",
      id: "msg-123",
      sender: "GitHub",
      senderDomain: "github.com",
      senderVerified: true,
      code: "892147",
      account: "personal",
      receivedAt: 1700000000000,
      raw: "Your code is 892147"
    };

    const msgWithDomain = parseIncomingMessage(JSON.stringify(otpPayloadWithDomain));
    expect(msgWithDomain).toEqual(otpPayloadWithDomain);

    const otpPayloadWithoutDomain = {
      type: "otp",
      id: "msg-124",
      sender: "Google",
      code: "123456",
      account: "work",
      receivedAt: 1700000000000
    };
    expect(parseIncomingMessage(JSON.stringify(otpPayloadWithoutDomain))).toEqual({
      ...otpPayloadWithoutDomain,
      senderDomain: null,
      senderVerified: false,
      raw: undefined
    });

    const otpPayloadInvalidDomain = {
      type: "otp",
      sender: "Service",
      senderDomain: "not a domain!",
      code: "654321",
      account: "test",
      receivedAt: 1700000000000
    };
    expect(parseIncomingMessage(otpPayloadInvalidDomain)).toEqual({
      type: "otp",
      id: undefined,
      sender: "Service",
      senderDomain: null,
      senderVerified: false,
      code: "654321",
      account: "test",
      receivedAt: 1700000000000,
      raw: undefined
    });
  });

  it("validates senderVerified as boolean or defaults to false", () => {
    const base = {
      type: "otp",
      sender: "GitHub",
      code: "123456",
      account: "personal",
      receivedAt: 1700000000000
    };

    expect(parseIncomingMessage({ ...base, senderVerified: true })?.senderVerified).toBe(true);
    expect(parseIncomingMessage({ ...base, senderVerified: false })?.senderVerified).toBe(false);
    expect(parseIncomingMessage({ ...base, senderVerified: "true" })?.senderVerified).toBe(false);
    expect(parseIncomingMessage({ ...base, senderVerified: 1 })?.senderVerified).toBe(false);
    expect(parseIncomingMessage({ ...base, senderVerified: null })?.senderVerified).toBe(false);
    expect(parseIncomingMessage({ ...base, senderVerified: undefined })?.senderVerified).toBe(false);
    expect(parseIncomingMessage({ ...base, senderVerified: {} })?.senderVerified).toBe(false);
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

describe("Domain Matching (domainsMatch & getRegistrableDomain)", () => {
  it("extracts registrable domain for standard domains", () => {
    expect(getRegistrableDomain("github.com")).toBe("github.com");
    expect(getRegistrableDomain("mail.github.com")).toBe("github.com");
    expect(getRegistrableDomain("sub.deep.mail.github.com")).toBe("github.com");
    expect(getRegistrableDomain("google.com")).toBe("google.com");
    expect(getRegistrableDomain("accounts.google.com")).toBe("google.com");
  });

  it("extracts registrable domain for multi-part public suffixes", () => {
    // ccTLDs
    expect(getRegistrableDomain("shop.co.uk")).toBe("shop.co.uk");
    expect(getRegistrableDomain("sub.shop.co.uk")).toBe("shop.co.uk");
    expect(getRegistrableDomain("example.org.uk")).toBe("example.org.uk");
    expect(getRegistrableDomain("example.ac.uk")).toBe("example.ac.uk");
    expect(getRegistrableDomain("example.gov.uk")).toBe("example.gov.uk");
    expect(getRegistrableDomain("example.com.au")).toBe("example.com.au");
    expect(getRegistrableDomain("example.net.au")).toBe("example.net.au");
    expect(getRegistrableDomain("example.co.jp")).toBe("example.co.jp");
    expect(getRegistrableDomain("example.co.in")).toBe("example.co.in");
    expect(getRegistrableDomain("example.co.za")).toBe("example.co.za");
    expect(getRegistrableDomain("example.com.br")).toBe("example.com.br");
    expect(getRegistrableDomain("example.com.et")).toBe("example.com.et");
    expect(getRegistrableDomain("example.gov.et")).toBe("example.gov.et");
    expect(getRegistrableDomain("example.edu.et")).toBe("example.edu.et");

    // Platforms
    expect(getRegistrableDomain("user1.github.io")).toBe("user1.github.io");
    expect(getRegistrableDomain("sub.user1.github.io")).toBe("user1.github.io");
    expect(getRegistrableDomain("app.vercel.app")).toBe("app.vercel.app");
    expect(getRegistrableDomain("site.netlify.app")).toBe("site.netlify.app");
    expect(getRegistrableDomain("my-app.pages.dev")).toBe("my-app.pages.dev");
    expect(getRegistrableDomain("test.herokuapp.com")).toBe("test.herokuapp.com");
    expect(getRegistrableDomain("blog.blogspot.com")).toBe("blog.blogspot.com");
    expect(getRegistrableDomain("project.web.app")).toBe("project.web.app");
    expect(getRegistrableDomain("project.firebaseapp.com")).toBe("project.firebaseapp.com");
  });

  it("returns null for multi-part public suffix with insufficient labels", () => {
    expect(getRegistrableDomain("co.uk")).toBeNull();
    expect(getRegistrableDomain("github.io")).toBeNull();
  });

  it("returns null for localhost, IP addresses, empty or invalid hostnames", () => {
    expect(getRegistrableDomain("localhost")).toBeNull();
    expect(getRegistrableDomain("foo.localhost")).toBeNull();
    expect(getRegistrableDomain("127.0.0.1")).toBeNull();
    expect(getRegistrableDomain("192.168.1.1")).toBeNull();
    expect(getRegistrableDomain("10.0.0.1")).toBeNull();
    expect(getRegistrableDomain("::1")).toBeNull();
    expect(getRegistrableDomain("")).toBeNull();
    expect(getRegistrableDomain("   ")).toBeNull();
    expect(getRegistrableDomain(null)).toBeNull();
    expect(getRegistrableDomain(undefined)).toBeNull();
    expect(getRegistrableDomain("com")).toBeNull();
  });

  it("domainsMatch tests specified in requirements", () => {
    // github.com vs github.com -> true
    expect(domainsMatch("github.com", "github.com")).toBe(true);
    // mail.github.com vs github.com -> true
    expect(domainsMatch("mail.github.com", "github.com")).toBe(true);
    // accounts.google.com vs accounts.google.com -> true
    expect(domainsMatch("accounts.google.com", "accounts.google.com")).toBe(true);
    // github.com vs github.com.evil.com -> false
    expect(domainsMatch("github.com", "github.com.evil.com")).toBe(false);
    // github.com vs evil-github.com -> false
    expect(domainsMatch("github.com", "evil-github.com")).toBe(false);
    // user1.github.io vs user2.github.io -> false
    expect(domainsMatch("user1.github.io", "user2.github.io")).toBe(false);
    // shop.co.uk vs evil.co.uk -> false
    expect(domainsMatch("shop.co.uk", "evil.co.uk")).toBe(false);
    // 127.0.0.1 and localhost -> false
    expect(domainsMatch("127.0.0.1", "127.0.0.1")).toBe(false);
    expect(domainsMatch("localhost", "localhost")).toBe(false);
    expect(domainsMatch("127.0.0.1", "localhost")).toBe(false);
    expect(domainsMatch("github.com", "127.0.0.1")).toBe(false);
    expect(domainsMatch("127.0.0.1", "github.com")).toBe(false);
  });

  it("domainsMatch handles null, undefined, empty and invalid domains correctly", () => {
    expect(domainsMatch(null, "github.com")).toBe(false);
    expect(domainsMatch("github.com", null)).toBe(false);
    expect(domainsMatch(null, null)).toBe(false);
    expect(domainsMatch(undefined, "github.com")).toBe(false);
    expect(domainsMatch("github.com", undefined)).toBe(false);
    expect(domainsMatch("", "github.com")).toBe(false);
    expect(domainsMatch("github.com", "")).toBe(false);
    expect(domainsMatch("invalid_host", "github.com")).toBe(false);
  });

  it("verifies all required public suffixes are present in MULTI_PART_PUBLIC_SUFFIXES", () => {
    const requiredSuffixes = [
      "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.in",
      "co.za", "com.br", "com.et", "gov.et", "edu.et", "github.io", "vercel.app",
      "netlify.app", "pages.dev", "herokuapp.com", "blogspot.com", "web.app", "firebaseapp.com"
    ];
    for (const suffix of requiredSuffixes) {
      expect(MULTI_PART_PUBLIC_SUFFIXES.has(suffix)).toBe(true);
    }
  });
});

describe("decideAutofill", () => {
  const baseParams = {
    askFirst: false,
    protocol: "https:",
    hostname: "github.com",
    senderDomain: "github.com",
    senderVerified: true,
    ageMs: 5000,
    used: false
  };

  it("returns 'auto' when all conditions are fresh and matching", () => {
    expect(decideAutofill(baseParams)).toBe("auto");
    expect(decideAutofill({ ...baseParams, hostname: "mail.github.com" })).toBe("auto");
  });

  it("returns 'none' when ageMs > 10 minutes (600,000 ms)", () => {
    expect(decideAutofill({ ...baseParams, ageMs: 600001 })).toBe("none");
    expect(decideAutofill({ ...baseParams, ageMs: 660000 })).toBe("none");
    expect(decideAutofill({ ...baseParams, ageMs: 1000000 })).toBe("none");
  });

  it("prioritizes ageMs > 10 minutes 'none' over any other setting", () => {
    expect(
      decideAutofill({
        ...baseParams,
        ageMs: 660000,
        askFirst: true,
        protocol: "http:",
        used: true,
        senderDomain: "evil.com",
        senderVerified: false
      })
    ).toBe("none");
  });

  it("returns 'manual' when senderVerified is not true", () => {
    expect(decideAutofill({ ...baseParams, senderVerified: false })).toBe("manual");
    expect(decideAutofill({ ...baseParams, senderVerified: undefined })).toBe("manual");
  });

  it("returns 'manual' when askFirst is true", () => {
    expect(decideAutofill({ ...baseParams, askFirst: true })).toBe("manual");
  });

  it("returns 'manual' when protocol !== 'https:'", () => {
    expect(decideAutofill({ ...baseParams, protocol: "http:" })).toBe("manual");
    expect(decideAutofill({ ...baseParams, protocol: "chrome-extension:" })).toBe("manual");
    expect(decideAutofill({ ...baseParams, protocol: "" })).toBe("manual");
  });

  it("returns 'manual' when used is true", () => {
    expect(decideAutofill({ ...baseParams, used: true })).toBe("manual");
  });

  it("returns 'manual' when senderDomain is null or undefined or mismatched", () => {
    expect(decideAutofill({ ...baseParams, senderDomain: null })).toBe("manual");
    expect(decideAutofill({ ...baseParams, senderDomain: "" })).toBe("manual");
    expect(decideAutofill({ ...baseParams, hostname: "evil.com" })).toBe("manual");
    expect(decideAutofill({ ...baseParams, hostname: "github.com.evil.com" })).toBe("manual");
  });

  it("returns 'manual' when ageMs > 2 minutes (120,000 ms) and <= 10 minutes", () => {
    expect(decideAutofill({ ...baseParams, ageMs: 120001 })).toBe("manual");
    expect(decideAutofill({ ...baseParams, ageMs: 180000 })).toBe("manual");
    expect(decideAutofill({ ...baseParams, ageMs: 600000 })).toBe("manual");
  });

  it("returns 'auto' when ageMs is exactly 2 minutes (120,000 ms)", () => {
    expect(decideAutofill({ ...baseParams, ageMs: 120000 })).toBe("auto");
  });

  it("matches the exact verification table from instructions", () => {
    const b = {
      askFirst: false,
      protocol: "https:",
      hostname: "github.com",
      senderDomain: "github.com",
      senderVerified: true,
      ageMs: 5000,
      used: false
    };
    const cases: Array<[string, Partial<typeof b>, string]> = [
      ["match", {}, "auto"],
      ["evil host", { hostname: "evil.com" }, "manual"],
      ["http", { protocol: "http:" }, "manual"],
      ["askFirst", { askFirst: true }, "manual"],
      ["3 min old", { ageMs: 180000 }, "manual"],
      ["11 min old", { ageMs: 660000 }, "none"],
      ["used", { used: true }, "manual"],
      ["unverified", { senderVerified: false }, "manual"],
      ["unverified but 11 min old", { senderVerified: false, ageMs: 660000 }, "none"],
      ["verified true", { senderVerified: true }, "auto"]
    ];

    for (const [, override, expected] of cases) {
      expect(decideAutofill({ ...b, ...override })).toBe(expected);
    }
  });
});

describe("scoreField", () => {
  it("assigns highest score (>= 100) to autocomplete='one-time-code'", () => {
    const score1 = scoreField({ autocomplete: "one-time-code", visible: true });
    expect(score1).toBeGreaterThanOrEqual(100);

    const score2 = scoreField({
      type: "text",
      autocomplete: "ONE-TIME-CODE",
      maxLength: 6,
      visible: true
    });
    expect(score2).toBeGreaterThanOrEqual(100);

    const regexOnlyScore = scoreField({
      type: "text",
      name: "otp",
      visible: true
    });
    expect(score1).toBeGreaterThan(regexOnlyScore);
  });

  it("accepts inputs matching OTP regex on name, id, placeholder, or ariaLabel", () => {
    expect(scoreField({ type: "text", name: "otp", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", name: "one-time-passcode", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", name: "onetime_code", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", id: "user_verification", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", id: "verify_input", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", name: "passcode", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", name: "2fa", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", id: "security-code", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", id: "security_code", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", placeholder: "Enter code here", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", ariaLabel: "Verification code", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "text", "aria-label": "Enter your OTP", visible: true })).toBeGreaterThan(0);
  });

  it("accepts type text, tel, number, and unset type", () => {
    expect(scoreField({ type: "text", name: "otp", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "tel", name: "otp", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ type: "number", name: "otp", visible: true })).toBeGreaterThan(0);
    expect(scoreField({ name: "otp", visible: true })).toBeGreaterThan(0);
  });

  it("accepts maxLength 4-10 or unset", () => {
    expect(scoreField({ name: "otp", maxLength: 4, visible: true })).toBeGreaterThan(0);
    expect(scoreField({ name: "otp", maxLength: 6, visible: true })).toBeGreaterThan(0);
    expect(scoreField({ name: "otp", maxLength: 8, visible: true })).toBeGreaterThan(0);
    expect(scoreField({ name: "otp", maxLength: 10, visible: true })).toBeGreaterThan(0);
    expect(scoreField({ name: "otp", maxLength: undefined, visible: true })).toBeGreaterThan(0);
    expect(scoreField({ name: "otp", maxLength: -1, visible: true })).toBeGreaterThan(0);
    expect(scoreField({ name: "otp", maxLength: 524288, visible: true })).toBeGreaterThan(0);
  });

  it("rejects password, email, hidden, and invisible inputs", () => {
    expect(scoreField({ type: "password", name: "otp", visible: true })).toBe(0);
    expect(scoreField({ type: "email", name: "otp", visible: true })).toBe(0);
    expect(scoreField({ type: "hidden", name: "otp", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "otp", visible: false })).toBe(0);
    expect(scoreField({ type: "checkbox", name: "otp", visible: true })).toBe(0);
    expect(scoreField({ type: "submit", name: "otp", visible: true })).toBe(0);
  });

  it("rejects names matching /search|coupon|promo|zip|postal|phone|card|cvv|cvc/i", () => {
    expect(scoreField({ type: "text", name: "search", autocomplete: "one-time-code", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "site_search_query", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "coupon_code", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "promo_code", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "zip_code", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "postal_code", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "phone_number", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "credit_card_code", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "card_cvv", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "card_cvc", visible: true })).toBe(0);
  });

  it("rejects non-segmented maxLength outside 4-10 range", () => {
    expect(scoreField({ type: "text", name: "otp", maxLength: 1, visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "otp", maxLength: 2, visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "otp", maxLength: 3, visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "otp", maxLength: 11, visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "otp", maxLength: 20, visible: true })).toBe(0);
  });

  it("returns 0 for irrelevant inputs", () => {
    expect(scoreField({ type: "text", name: "username", visible: true })).toBe(0);
    expect(scoreField({ type: "text", name: "first_name", visible: true })).toBe(0);
    expect(scoreField({ type: "text", placeholder: "Your email address", visible: true })).toBe(0);
  });
});

describe("groupSegmented", () => {
  const makeSegInput = (id: string, overrides: Partial<FieldDescriptor> = {}): FieldDescriptor => ({
    id,
    type: "text",
    maxLength: 1,
    visible: true,
    ...overrides
  });

  it("detects 4, 6, and 8 consecutive single-character inputs", () => {
    const group4 = [makeSegInput("s1"), makeSegInput("s2"), makeSegInput("s3"), makeSegInput("s4")];
    expect(groupSegmented(group4)).toHaveLength(1);
    expect(groupSegmented(group4)[0]).toHaveLength(4);

    const group6 = [
      makeSegInput("s1"),
      makeSegInput("s2"),
      makeSegInput("s3"),
      makeSegInput("s4"),
      makeSegInput("s5"),
      makeSegInput("s6")
    ];
    expect(groupSegmented(group6)).toHaveLength(1);
    expect(groupSegmented(group6)[0]).toHaveLength(6);

    const group8 = Array.from({ length: 8 }, (_, i) => makeSegInput(`s${i}`));
    expect(groupSegmented(group8)).toHaveLength(1);
    expect(groupSegmented(group8)[0]).toHaveLength(8);
  });

  it("does not detect groups with fewer than 4 or more than 8 inputs", () => {
    const group3 = [makeSegInput("s1"), makeSegInput("s2"), makeSegInput("s3")];
    expect(groupSegmented(group3)).toHaveLength(0);

    const group9 = Array.from({ length: 9 }, (_, i) => makeSegInput(`s${i}`));
    expect(groupSegmented(group9)).toHaveLength(0);

    const group10 = Array.from({ length: 10 }, (_, i) => makeSegInput(`s${i}`));
    expect(groupSegmented(group10)).toHaveLength(0);
  });

  it("breaks consecutive run when an input is invisible or non-single-char", () => {
    const brokenInvisible = [
      makeSegInput("s1"),
      makeSegInput("s2"),
      makeSegInput("s3"),
      makeSegInput("s4", { visible: false }),
      makeSegInput("s5"),
      makeSegInput("s6")
    ];
    expect(groupSegmented(brokenInvisible)).toHaveLength(0);

    const brokenMaxLength = [
      makeSegInput("s1"),
      makeSegInput("s2"),
      makeSegInput("s3"),
      makeSegInput("s4", { maxLength: 2 }),
      makeSegInput("s5"),
      makeSegInput("s6")
    ];
    expect(groupSegmented(brokenMaxLength)).toHaveLength(0);

    const brokenType = [
      makeSegInput("s1"),
      makeSegInput("s2"),
      makeSegInput("s3"),
      makeSegInput("s4", { type: "password" }),
      makeSegInput("s5"),
      makeSegInput("s6")
    ];
    expect(groupSegmented(brokenType)).toHaveLength(0);
  });

  it("detects multiple independent groups separated by other elements", () => {
    const mixed = [
      makeSegInput("a1"),
      makeSegInput("a2"),
      makeSegInput("a3"),
      makeSegInput("a4"),
      makeSegInput("a5"),
      makeSegInput("a6"),
      { type: "text", name: "other", maxLength: 20, visible: true },
      makeSegInput("b1"),
      makeSegInput("b2"),
      makeSegInput("b3"),
      makeSegInput("b4")
    ];
    const detected = groupSegmented(mixed);
    expect(detected).toHaveLength(2);
    expect(detected[0]).toHaveLength(6);
    expect(detected[1]).toHaveLength(4);
  });

  it("returns empty array for empty inputs", () => {
    expect(groupSegmented([])).toHaveLength(0);
  });
});

describe("Message Validation", () => {
  it("validates fields message correctly", () => {
    expect(validateFieldsMessage({ type: "fields", present: true })).toEqual({
      type: "fields",
      present: true
    });
    expect(validateFieldsMessage({ type: "fields", present: false })).toEqual({
      type: "fields",
      present: false
    });

    expect(validateFieldsMessage({ type: "fields" })).toBeNull();
    expect(validateFieldsMessage({ type: "fields", present: "true" })).toBeNull();
    expect(validateFieldsMessage({ type: "other", present: true })).toBeNull();
    expect(validateFieldsMessage(null)).toBeNull();
    expect(validateFieldsMessage("invalid")).toBeNull();
  });

  it("validates fill message correctly with 4-10 alphanumeric codes", () => {
    expect(validateFillMessage({ type: "fill", code: "1234" })).toEqual({
      type: "fill",
      code: "1234"
    });
    expect(validateFillMessage({ type: "fill", code: "892147" })).toEqual({
      type: "fill",
      code: "892147"
    });
    expect(validateFillMessage({ type: "fill", code: "ABCDEF12" })).toEqual({
      type: "fill",
      code: "ABCDEF12"
    });
    expect(validateFillMessage({ type: "fill", code: "0123456789" })).toEqual({
      type: "fill",
      code: "0123456789"
    });

    // Too short (< 4)
    expect(validateFillMessage({ type: "fill", code: "123" })).toBeNull();
    // Too long (> 10)
    expect(validateFillMessage({ type: "fill", code: "12345678901" })).toBeNull();
    // Special characters
    expect(validateFillMessage({ type: "fill", code: "123-456" })).toBeNull();
    expect(validateFillMessage({ type: "fill", code: "123 456" })).toBeNull();
    // Non-string code
    expect(validateFillMessage({ type: "fill", code: 123456 })).toBeNull();
    // Wrong type
    expect(validateFillMessage({ type: "not-fill", code: "123456" })).toBeNull();
    expect(validateFillMessage(null)).toBeNull();
    expect(validateFillMessage({})).toBeNull();
  });
});

describe("deriveViewState", () => {
  const makeLatest = (senderDomain: string | null = "github.com", overrides = {}) => ({
    senderDomain,
    senderVerified: true,
    code: "123456",
    ageMs: 5000,
    used: false,
    ...overrides
  });

  const makeTab = (hostname: string | null = "github.com", present = true) => ({
    hostname,
    present
  });

  it("handles tab.hostname null: fillEnabled false, showMismatchWarning false, and inactive hint", () => {
    const res = deriveViewState({
      status: "connected",
      latest: makeLatest(),
      tab: { hostname: null, present: false },
      askFirst: false
    });

    expect(res).toEqual({
      fillEnabled: false,
      fillLabel: "Fill",
      showMismatchWarning: false,
      showUnverifiedWarning: false,
      hint: "AutoOTP isn't active on this page. Reload it, or it may not be an https page."
    });
  });

  it("handles empty tab.hostname string as null", () => {
    const res = deriveViewState({
      status: "connected",
      latest: makeLatest(),
      tab: { hostname: "", present: false },
      askFirst: false
    });

    expect(res.fillEnabled).toBe(false);
    expect(res.showMismatchWarning).toBe(false);
    expect(res.showUnverifiedWarning).toBe(false);
    expect(res.hint).toBe("AutoOTP isn't active on this page. Reload it, or it may not be an https page.");
  });

  it("handles hostname known but present false: fillEnabled false, showMismatchWarning false, and no field hint", () => {
    const res = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com"),
      tab: makeTab("github.com", false),
      askFirst: false
    });

    expect(res).toEqual({
      fillEnabled: false,
      fillLabel: "Fill",
      showMismatchWarning: false,
      showUnverifiedWarning: false,
      hint: "No code field found on this page"
    });

    // Even if domains mismatch, warning is false and hint is no field found
    const resMismatch = deriveViewState({
      status: "connected",
      latest: makeLatest("gmail.com"),
      tab: makeTab("github.com", false),
      askFirst: false
    });

    expect(resMismatch.fillEnabled).toBe(false);
    expect(resMismatch.showMismatchWarning).toBe(false);
    expect(resMismatch.showUnverifiedWarning).toBe(false);
    expect(resMismatch.hint).toBe("No code field found on this page");
  });

  it("handles present true and sender matches (domainsMatch): fillEnabled true, fillLabel 'Fill', no warning", () => {
    const res = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com"),
      tab: makeTab("github.com", true),
      askFirst: false
    });

    expect(res).toEqual({
      fillEnabled: true,
      fillLabel: "Fill",
      showMismatchWarning: false,
      showUnverifiedWarning: false,
      hint: null
    });

    // Subdomain matching registrable domain
    const resSub = deriveViewState({
      status: "connected",
      latest: makeLatest("mail.github.com"),
      tab: makeTab("github.com", true),
      askFirst: false
    });

    expect(resSub.fillEnabled).toBe(true);
    expect(resSub.fillLabel).toBe("Fill");
    expect(resSub.showMismatchWarning).toBe(false);
    expect(resSub.showUnverifiedWarning).toBe(false);
    expect(resSub.hint).toBeNull();
  });

  it("handles present true and sender is null or does not match: fillEnabled true, fillLabel 'Fill anyway', showMismatchWarning true", () => {
    const resNullSender = deriveViewState({
      status: "connected",
      latest: makeLatest(null),
      tab: makeTab("github.com", true),
      askFirst: false
    });

    expect(resNullSender).toEqual({
      fillEnabled: true,
      fillLabel: "Fill anyway",
      showMismatchWarning: true,
      showUnverifiedWarning: false,
      hint: null
    });

    const resMismatchedDomain = deriveViewState({
      status: "connected",
      latest: makeLatest("gmail.com"),
      tab: makeTab("github.com", true),
      askFirst: false
    });

    expect(resMismatchedDomain).toEqual({
      fillEnabled: true,
      fillLabel: "Fill anyway",
      showMismatchWarning: true,
      showUnverifiedWarning: false,
      hint: null
    });

    const resEvil = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com"),
      tab: makeTab("github.com.evil.com", true),
      askFirst: false
    });

    expect(resEvil.fillEnabled).toBe(true);
    expect(resEvil.fillLabel).toBe("Fill anyway");
    expect(resEvil.showMismatchWarning).toBe(true);
    expect(resEvil.showUnverifiedWarning).toBe(false);
  });

  it("handles no latest code or code older than 10 minutes: fillEnabled false and no warning", () => {
    const resNoLatest = deriveViewState({
      status: "connected",
      latest: null,
      tab: makeTab("github.com", true),
      askFirst: false
    });

    expect(resNoLatest).toEqual({
      fillEnabled: false,
      fillLabel: "Fill",
      showMismatchWarning: false,
      showUnverifiedWarning: false,
      hint: null
    });

    const resStale = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com", { ageMs: 660000 }),
      tab: makeTab("github.com", true),
      askFirst: false
    });

    expect(resStale).toEqual({
      fillEnabled: false,
      fillLabel: "Fill",
      showMismatchWarning: false,
      showUnverifiedWarning: false,
      hint: null
    });

    // Even on domain mismatch, if expired, warning is false and fillEnabled is false
    const resStaleMismatch = deriveViewState({
      status: "connected",
      latest: makeLatest("gmail.com", { ageMs: 700000 }),
      tab: makeTab("github.com", true),
      askFirst: false
    });

    expect(resStaleMismatch.fillEnabled).toBe(false);
    expect(resStaleMismatch.showMismatchWarning).toBe(false);
    expect(resStaleMismatch.showUnverifiedWarning).toBe(false);
    expect(resStaleMismatch.hint).toBeNull();

    // Exactly 10 minutes (600,000 ms) is still accepted
    const resExact10m = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com", { ageMs: 600000 }),
      tab: makeTab("github.com", true),
      askFirst: false
    });
    expect(resExact10m.fillEnabled).toBe(true);

    // 10 minutes + 1 ms is expired
    const resJustExpired = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com", { ageMs: 600001 }),
      tab: makeTab("github.com", true),
      askFirst: false
    });
    expect(resJustExpired.fillEnabled).toBe(false);
  });

  it("verifies the exact cases from verification script b", () => {
    const L = (s: string | null) => ({
      senderDomain: s,
      senderVerified: true,
      code: "123456",
      ageMs: 5000,
      used: false
    });
    const T = (h: string | null, p: boolean) => ({ hostname: h, present: p });

    expect(
      deriveViewState({
        status: "connected",
        latest: L("github.com"),
        tab: T("github.com", true),
        askFirst: false
      })
    ).toEqual({
      fillEnabled: true,
      fillLabel: "Fill",
      showMismatchWarning: false,
      showUnverifiedWarning: false,
      hint: null
    });

    expect(
      deriveViewState({
        status: "connected",
        latest: L("gmail.com"),
        tab: T("github.com", true),
        askFirst: false
      })
    ).toEqual({
      fillEnabled: true,
      fillLabel: "Fill anyway",
      showMismatchWarning: true,
      showUnverifiedWarning: false,
      hint: null
    });

    expect(
      deriveViewState({
        status: "connected",
        latest: L("gmail.com"),
        tab: T("github.com", false),
        askFirst: false
      })
    ).toEqual({
      fillEnabled: false,
      fillLabel: "Fill",
      showMismatchWarning: false,
      showUnverifiedWarning: false,
      hint: "No code field found on this page"
    });

    expect(
      deriveViewState({
        status: "connected",
        latest: L("gmail.com"),
        tab: T(null, false),
        askFirst: false
      })
    ).toEqual({
      fillEnabled: false,
      fillLabel: "Fill",
      showMismatchWarning: false,
      showUnverifiedWarning: false,
      hint: "AutoOTP isn't active on this page. Reload it, or it may not be an https page."
    });
  });

  it("adds showUnverifiedWarning true when field is present and senderVerified is false", () => {
    // 1. matching domain, unverified -> showUnverifiedWarning: true, fillLabel: 'Fill anyway', showMismatchWarning: false
    const resMatchingUnverified = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com", { senderVerified: false }),
      tab: makeTab("github.com", true),
      askFirst: false
    });
    expect(resMatchingUnverified).toEqual({
      fillEnabled: true,
      fillLabel: "Fill anyway",
      showMismatchWarning: false,
      showUnverifiedWarning: true,
      hint: null
    });

    // 2. mismatching domain, unverified -> showUnverifiedWarning: true, fillLabel: 'Fill anyway', showMismatchWarning: true
    const resMismatchUnverified = deriveViewState({
      status: "connected",
      latest: makeLatest("gmail.com", { senderVerified: false }),
      tab: makeTab("github.com", true),
      askFirst: false
    });
    expect(resMismatchUnverified).toEqual({
      fillEnabled: true,
      fillLabel: "Fill anyway",
      showMismatchWarning: true,
      showUnverifiedWarning: true,
      hint: null
    });

    // 3. matching domain, verified true -> showUnverifiedWarning: false, fillLabel: 'Fill', showMismatchWarning: false
    const resVerified = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com", { senderVerified: true }),
      tab: makeTab("github.com", true),
      askFirst: false
    });
    expect(resVerified).toEqual({
      fillEnabled: true,
      fillLabel: "Fill",
      showMismatchWarning: false,
      showUnverifiedWarning: false,
      hint: null
    });

    // 4. field not present, unverified -> showUnverifiedWarning: false
    const resNoField = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com", { senderVerified: false }),
      tab: makeTab("github.com", false),
      askFirst: false
    });
    expect(resNoField.showUnverifiedWarning).toBe(false);
    expect(resNoField.fillEnabled).toBe(false);

    // 5. tab.hostname null, unverified -> showUnverifiedWarning: false
    const resNoHost = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com", { senderVerified: false }),
      tab: { hostname: null, present: false },
      askFirst: false
    });
    expect(resNoHost.showUnverifiedWarning).toBe(false);

    // 6. expired code (>10m), unverified -> showUnverifiedWarning: false
    const resExpired = deriveViewState({
      status: "connected",
      latest: makeLatest("github.com", { senderVerified: false, ageMs: 700000 }),
      tab: makeTab("github.com", true),
      askFirst: false
    });
    expect(resExpired.showUnverifiedWarning).toBe(false);
    expect(resExpired.fillEnabled).toBe(false);
  });
});

describe("formatUsedFeedback", () => {
  it("formats automatic fill feedback with seconds and minutes", () => {
    expect(
      formatUsedFeedback({
        usedHostname: "github.com",
        usedAgoMs: 5000,
        usedAuto: true
      })
    ).toBe("Filled automatically on github.com 5s ago");

    expect(
      formatUsedFeedback({
        usedHostname: "accounts.google.com",
        usedAgoMs: 45000,
        usedAuto: true
      })
    ).toBe("Filled automatically on accounts.google.com 45s ago");

    expect(
      formatUsedFeedback({
        usedHostname: "github.com",
        usedAgoMs: 120000,
        usedAuto: true
      })
    ).toBe("Filled automatically on github.com 2m ago");
  });

  it("formats manual fill feedback with seconds and minutes", () => {
    expect(
      formatUsedFeedback({
        usedHostname: "github.com",
        usedAgoMs: 10000,
        usedAuto: false
      })
    ).toBe("Filled on github.com 10s ago");

    expect(
      formatUsedFeedback({
        usedHostname: "example.com",
        usedAgoMs: 180000,
        usedAuto: false
      })
    ).toBe("Filled on example.com 3m ago");
  });

  it("computes age from usedAt timestamp when usedAgoMs is not provided", () => {
    const now = 1700000050000;
    const usedAt = 1700000042000; // 8s ago
    expect(
      formatUsedFeedback(
        {
          usedHostname: "github.com",
          usedAt,
          usedAuto: true
        },
        now
      )
    ).toBe("Filled automatically on github.com 8s ago");
  });

  it("returns null if latest is null or usedHostname is not present", () => {
    expect(formatUsedFeedback(null)).toBeNull();
    expect(formatUsedFeedback(undefined)).toBeNull();
    expect(formatUsedFeedback({ usedHostname: undefined })).toBeNull();
    expect(formatUsedFeedback({ usedHostname: "" })).toBeNull();
  });

  it("integrates used feedback into deriveViewState when usedHostname is present", () => {
    const res = deriveViewState({
      status: "connected",
      latest: {
        senderDomain: "github.com",
        ageMs: 5000,
        used: true,
        usedHostname: "github.com",
        usedAgoMs: 12000,
        usedAuto: true
      },
      tab: { hostname: "github.com", present: true },
      askFirst: false
    });

    expect(res.usedFeedback).toBe("Filled automatically on github.com 12s ago");
  });
});

describe("Browser Extension Icons", () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const manifestPath = path.join(root, "manifest.json");

  it("manifest.json defines icons and action.default_icon with 16, 24, 32, 48, 128", () => {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    expect(manifest.icons).toBeDefined();
    expect(manifest.action?.default_icon).toBeDefined();

    for (const size of ["16", "24", "32", "48", "128"]) {
      expect(manifest.icons[size]).toBe(`icons/icon-${size}.png`);
      expect(manifest.action.default_icon[size]).toBe(`icons/icon-${size}.png`);

      const iconPath = path.join(root, manifest.icons[size]);
      expect(fs.existsSync(iconPath), `Icon file ${iconPath} must exist`).toBe(true);
    }
  });
});



