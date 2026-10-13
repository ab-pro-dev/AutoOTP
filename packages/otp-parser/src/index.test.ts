import { describe, it, expect } from "vitest";
import { extractOtp } from "./index.js";

describe("extractOtp", () => {
  describe("Sample sentences", () => {
    it("extracts OTP from 'Your verification code is 483921.'", () => {
      const result = extractOtp({ body: "Your verification code is 483921." });
      expect(result).toEqual({
        code: "483921",
        raw: "483921",
        confidence: "high"
      });
    });

    it("extracts OTP from 'Use 483921 to continue.'", () => {
      const result = extractOtp({ body: "Use 483921 to continue." });
      expect(result).toEqual({
        code: "483921",
        raw: "483921",
        confidence: "high"
      });
    });

    it("extracts OTP from 'Enter code: 483921'", () => {
      const result = extractOtp({ body: "Enter code: 483921" });
      expect(result).toEqual({
        code: "483921",
        raw: "483921",
        confidence: "high"
      });
    });
  });

  describe("Candidate shapes", () => {
    it("extracts dashed code 456-821 normalized to 456821", () => {
      const result = extractOtp({ body: "Your security code is 456-821" });
      expect(result).toEqual({
        code: "456821",
        raw: "456-821",
        confidence: "high"
      });
    });

    it("extracts spaced code 123 456 normalized to 123456", () => {
      const result = extractOtp({ body: "Your passcode is 123 456" });
      expect(result).toEqual({
        code: "123456",
        raw: "123 456",
        confidence: "high"
      });
    });

    it("extracts uppercase alphanumeric code A92B13", () => {
      const result = extractOtp({ body: "Your verification code is A92B13" });
      expect(result).toEqual({
        code: "A92B13",
        raw: "A92B13",
        confidence: "high"
      });
    });

    it("extracts an 8-digit code", () => {
      const result = extractOtp({ body: "Please enter verification code 12345678" });
      expect(result).toEqual({
        code: "12345678",
        raw: "12345678",
        confidence: "high"
      });
    });

    it("supports G-482913 prefix and strips G-", () => {
      const result = extractOtp({ body: "G-482913 is your Google verification code" });
      expect(result).toEqual({
        code: "482913",
        raw: "G-482913",
        confidence: "high"
      });
    });

    it("supports multi-dash groups like 91-47-22", () => {
      const result = extractOtp({ body: "Security code: 91-47-22 expires in 10 minutes" });
      expect(result).toEqual({
        code: "914722",
        raw: "91-47-22",
        confidence: "high"
      });
    });
  });

  describe("Negative rejection cases", () => {
    it("rejects order numbers prefixed with #", () => {
      expect(extractOtp({ body: "Order #123456 has shipped" })).toBeNull();
      expect(extractOtp({ body: "Your order #482913 has shipped" })).toBeNull();
    });

    it("rejects 4-digit years (1990-2100)", () => {
      expect(extractOtp({ body: "Copyright 2026" })).toBeNull();
      expect(extractOtp({ body: "Happy new year 2026!" })).toBeNull();
      expect(extractOtp({ body: "Established in 1999" })).toBeNull();
    });

    it("rejects phone numbers", () => {
      expect(extractOtp({ body: "Call 555-123-4567" })).toBeNull();
      expect(extractOtp({ body: "Call (555) 123-4567" })).toBeNull();
    });

    it("returns null for email with no code or numbers", () => {
      expect(extractOtp({ body: "Thank you for subscribing to our newsletter!" })).toBeNull();
    });

    it("rejects amounts with currency symbols", () => {
      expect(extractOtp({ body: "Your verification refund is $123456." })).toBeNull();
      expect(extractOtp({ body: "Total security payment: 456789 €" })).toBeNull();
    });

    it("rejects numbers with 9 or more digits", () => {
      expect(extractOtp({ body: "Your verification code is 1234567890." })).toBeNull();
    });
  });

  describe("Multi-candidate & Confidence handling", () => {
    it("prioritizes keyword-adjacent candidate over medium confidence candidate", () => {
      const result = extractOtp({
        subject: "Your Account Verification",
        body: "Reference ID: 987654. Your security code is 483921."
      });
      expect(result).toEqual({
        code: "483921",
        raw: "483921",
        confidence: "high"
      });
    });

    it("breaks ties between high confidence candidates using first occurrence", () => {
      const result = extractOtp({
        body: "Your verification codes are 111111 and 222222."
      });
      expect(result).toEqual({
        code: "111111",
        raw: "111111",
        confidence: "high"
      });
    });

    it("assigns medium confidence to bare 6-digit number when subject has keyword", () => {
      const result = extractOtp({
        subject: "Your verification code",
        body: "Hello,\n\n483921\n\nThanks"
      });
      expect(result).toEqual({
        code: "483921",
        raw: "483921",
        confidence: "medium"
      });
    });

    it("ignores candidate appearing beyond 5000 character limit", () => {
      const padding = "a".repeat(5000);
      const result = extractOtp({
        body: `${padding} Your verification code is 483921.`
      });
      expect(result).toBeNull();
    });
  });
});
