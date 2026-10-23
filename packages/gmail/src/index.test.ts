import fs from "node:fs";
import path from "node:path";
import { getEventListeners } from "node:events";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { TokenStore } from "@autootp/shared";
import {
  createVerifier,
  createChallenge,
  createState,
  loadCredentials,
  loginWithBrowser,
  refreshAccessToken,
  ReauthRequiredError,
  watchAccount,
  htmlToText,
  parseSender,
  parseSenderDomain,
  isSenderVerified,
  OtpNotification
} from "./index.js";

describe("OAuth Login Flow (packages/gmail)", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-gmail-test-"));
    process.env.AUTOOTP_HOME = tempDir;

    // Create a mock credentials.json
    fs.writeFileSync(
      path.join(tempDir, "credentials.json"),
      JSON.stringify({
        installed: {
          client_id: "test-client-id.apps.googleusercontent.com",
          client_secret: "test-client-secret-123"
        }
      })
    );
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.AUTOOTP_HOME = originalHome;
    } else {
      delete process.env.AUTOOTP_HOME;
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("matches RFC 7636 PKCE test vector", () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    expect(createChallenge(verifier)).toBe(expectedChallenge);

    const generatedVerifier = createVerifier();
    expect(generatedVerifier.length).toBeGreaterThanOrEqual(43);
    const generatedState = createState();
    expect(generatedState.length).toBeGreaterThanOrEqual(43);
  });

  it("rejects when credentials.json is missing or invalid", () => {
    const emptyDir = fs.mkdtempSync(path.join(process.env.TMPDIR || "/tmp", "empty-creds-"));
    try {
      expect(() => loadCredentials(emptyDir)).toThrow(/credentials\.json/);

      fs.writeFileSync(
        path.join(emptyDir, "credentials.json"),
        JSON.stringify({ web: { client_id: "abc", client_secret: "xyz" } })
      );
      expect(() => loadCredentials(emptyDir)).toThrow(/found "web" client type/);

      fs.writeFileSync(
        path.join(emptyDir, "credentials.json"),
        JSON.stringify({ other: {} })
      );
      expect(() => loadCredentials(emptyDir)).toThrow(/missing "installed" key/);
    } finally {
      fs.rmSync(emptyDir, { recursive: true, force: true });
    }
  });

  it("auth URL contains exactly one scope, gmail.readonly", async () => {
    let capturedUrl = "";

    const promise = loginWithBrowser({
      accountId: "acc-scope",
      onAuthUrl: (url) => {
        capturedUrl = url;
      },
      timeoutMs: 100
    });

    await expect(promise).rejects.toThrow();

    const parsed = new URL(capturedUrl);
    expect(parsed.searchParams.get("scope")).toBe("https://www.googleapis.com/auth/gmail.readonly");
    expect(parsed.searchParams.getAll("scope")).toHaveLength(1);
  });

  it("the server rejects a wrong path and a wrong state with 400", async () => {
    let loopbackUrl = "";

    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({
            access_token: "mock-access-token",
            refresh_token: "mock-refresh-token",
            expires_in: 3600
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("gmail.googleapis.com/gmail/v1/users/me/profile")) {
        return new Response(
          JSON.stringify({ emailAddress: "alice@example.com" }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not found", { status: 404 });
    };

    const loginPromise = loginWithBrowser({
      accountId: "acc-reject-test",
      fetchImpl: mockFetch as typeof fetch,
      timeoutMs: 10000,
      onAuthUrl: async (url) => {
        const parsed = new URL(url);
        const redirect = parsed.searchParams.get("redirect_uri")!;
        const state = parsed.searchParams.get("state")!;
        loopbackUrl = new URL(redirect).origin;

        // 1. Send request to wrong path
        const wrongPathRes = await fetch(`${loopbackUrl}/unknown-path`);
        expect(wrongPathRes.status).toBe(400);

        // 2. Send request to /callback with wrong state
        const wrongStateRes = await fetch(`${loopbackUrl}/callback?state=wrong-state-xyz&code=abc`);
        expect(wrongStateRes.status).toBe(400);

        // 3. Send valid callback
        const validRes = await fetch(`${loopbackUrl}/callback?state=${state}&code=valid-code-123`);
        expect(validRes.status).toBe(200);
      }
    });

    const result = await loginPromise;
    expect(result.accountId).toBe("acc-reject-test");
    expect(result.email).toBe("alice@example.com");
  });

  it("happy path stores an encrypted token and returns the email", async () => {
    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({
            access_token: "access-token-999",
            refresh_token: "refresh-token-888",
            expires_in: 3600
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("gmail.googleapis.com/gmail/v1/users/me/profile")) {
        return new Response(
          JSON.stringify({ emailAddress: "user.happy@gmail.com" }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not Found", { status: 404 });
    };

    const result = await loginWithBrowser({
      accountId: "personal",
      fetchImpl: mockFetch as typeof fetch,
      onAuthUrl: async (authUrl) => {
        const parsed = new URL(authUrl);
        const redirectUri = parsed.searchParams.get("redirect_uri")!;
        const state = parsed.searchParams.get("state")!;

        const cbRes = await fetch(`${redirectUri}?state=${state}&code=valid-auth-code`);
        expect(cbRes.status).toBe(200);
      }
    });

    expect(result).toEqual({
      accountId: "personal",
      email: "user.happy@gmail.com"
    });

    const store = new TokenStore(tempDir);
    const stored = await store.get("personal");
    expect(stored?.refreshToken).toBe("refresh-token-888");
    expect(stored?.email).toBe("user.happy@gmail.com");
    expect(stored?.addedAt).toBeGreaterThan(0);
  });

  it("a response without a refresh_token errors", async () => {
    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({
            access_token: "access-token-only",
            expires_in: 3600
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not Found", { status: 404 });
    };

    const promise = loginWithBrowser({
      accountId: "no-refresh-acc",
      fetchImpl: mockFetch as typeof fetch,
      onAuthUrl: async (authUrl) => {
        const parsed = new URL(authUrl);
        const redirectUri = parsed.searchParams.get("redirect_uri")!;
        const state = parsed.searchParams.get("state")!;
        await fetch(`${redirectUri}?state=${state}&code=code-xyz`);
      }
    });

    await expect(promise).rejects.toThrow(/revoke app.*myaccount\.google\.com\/permissions/i);
  });

  it("timeout rejects and closes the server", async () => {
    let capturedRedirectUri = "";

    const promise = loginWithBrowser({
      accountId: "timeout-acc",
      timeoutMs: 50,
      onAuthUrl: (url) => {
        const parsed = new URL(url);
        capturedRedirectUri = parsed.searchParams.get("redirect_uri")!;
      }
    });

    await expect(promise).rejects.toThrow(/Login timed out/);

    // Verify the server was closed
    await expect(fetch(capturedRedirectUri)).rejects.toThrow();
  });

  it("refreshAccessToken exchanges refresh token and raises ReauthRequiredError on invalid_grant", async () => {
    const store = new TokenStore(tempDir);
    await store.set("acc-refresh", {
      refreshToken: "saved-refresh-token",
      email: "refreshed@example.com",
      addedAt: Date.now()
    });

    // 1. Successful refresh
    const mockSuccessFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({
          access_token: "new-access-token",
          expires_in: 3600
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    const refreshResult = await refreshAccessToken("acc-refresh", {
      fetchImpl: mockSuccessFetch as typeof fetch
    });
    expect(refreshResult.accessToken).toBe("new-access-token");
    expect(refreshResult.expiresIn).toBe(3600);

    // 2. invalid_grant error
    const mockInvalidGrantFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "Bad Request"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    };

    await expect(
      refreshAccessToken("acc-refresh", {
        fetchImpl: mockInvalidGrantFetch as typeof fetch
      })
    ).rejects.toThrow(ReauthRequiredError);
  });
});

describe("Gmail Watcher (packages/gmail)", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-watcher-test-"));
    process.env.AUTOOTP_HOME = tempDir;

    fs.writeFileSync(
      path.join(tempDir, "credentials.json"),
      JSON.stringify({
        installed: {
          client_id: "test-client-id.apps.googleusercontent.com",
          client_secret: "test-client-secret-123"
        }
      })
    );
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.AUTOOTP_HOME = originalHome;
    } else {
      delete process.env.AUTOOTP_HOME;
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("htmlToText strips scripts, styles, HTML tags and decodes entities", () => {
    const rawHtml = `
      <html>
        <head>
          <style>body { color: red; }</style>
          <script>console.log("secret");</script>
        </head>
        <body>
          <p>Your &lt;security&gt; code is: <strong>123456</strong> &amp; valid for 5 min.</p>
          <div>Don&#39;t share it.</div>
        </body>
      </html>
    `;
    const converted = htmlToText(rawHtml);
    expect(converted).not.toContain("color: red;");
    expect(converted).not.toContain("console.log");
    expect(converted).not.toContain("<p>");
    expect(converted).not.toContain("<strong>");
    expect(converted).toContain("Your <security> code is: 123456 & valid for 5 min.");
    expect(converted).toContain("Don't share it.");
  });

  it("parseSender extracts display name or falls back to email domain", () => {
    expect(parseSender('"GitHub" <noreply@github.com>')).toBe("GitHub");
    expect(parseSender("GitHub Security <security@github.com>")).toBe("GitHub Security");
    expect(parseSender("<support@stripe.com>")).toBe("stripe.com");
    expect(parseSender("auth@service.com")).toBe("service.com");
    expect(parseSender("")).toBe("unknown");
  });

  it("parseSenderDomain extracts valid domains, lowercases, and handles edge cases", () => {
    // Valid
    expect(parseSenderDomain("GitHub <noreply@github.com>")).toBe("github.com");
    // Uppercase
    expect(parseSenderDomain('"Bob" <Bob@Mail.Example.COM>')).toBe("mail.example.com");
    // Quoted name
    expect(parseSenderDomain('"Acme Support" <support@acme.org>')).toBe("acme.org");
    // Bare address
    expect(parseSenderDomain("user@service.io")).toBe("service.io");
    expect(parseSenderDomain("test@sub.domain.co.uk")).toBe("sub.domain.co.uk");
    // Garbage and invalid formats
    expect(parseSenderDomain("not an email")).toBeNull();
    expect(parseSenderDomain("just text without at")).toBeNull();
    expect(parseSenderDomain("")).toBeNull();
    expect(parseSenderDomain(undefined)).toBeNull();
    expect(parseSenderDomain("user@localhost")).toBeNull(); // no dot
    expect(parseSenderDomain("<>")).toBeNull();
    expect(parseSenderDomain("@")).toBeNull();
    expect(parseSenderDomain("user@")).toBeNull();
    expect(parseSenderDomain("@domain.com")).toBeNull();
    expect(parseSenderDomain("user@.com")).toBeNull();
    expect(parseSenderDomain("user@com.")).toBeNull();
  });

  it("dedupe: duplicate message returned across polls produces only one onOtp call", async () => {
    const store = new TokenStore(tempDir);
    await store.set("acc-dedupe", {
      refreshToken: "refresh-token-dedupe",
      email: "dedupe@example.com",
      addedAt: Date.now()
    });

    const otps: OtpNotification[] = [];
    const controller = new AbortController();
    let pollCount = 0;

    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/profile")) {
        return new Response(JSON.stringify({ historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/messages?labelIds=")) {
        return new Response(JSON.stringify({ messages: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/history")) {
        pollCount++;
        if (pollCount >= 3) {
          controller.abort();
        }
        return new Response(
          JSON.stringify({
            history: [{ messagesAdded: [{ message: { id: "msg-duplicate-1" } }] }],
            historyId: "101"
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/messages/msg-duplicate-1?format=full")) {
        return new Response(
          JSON.stringify({
            id: "msg-duplicate-1",
            internalDate: String(Date.now()),
            payload: {
              headers: [
                { name: "Subject", value: "Your verification code" },
                { name: "From", value: "Google <no-reply@accounts.google.com>" }
              ],
              mimeType: "text/plain",
              body: {
                data: Buffer.from("Your verification code is 456789.").toString("base64url")
              }
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not found", { status: 404 });
    };

    await watchAccount({
      accountId: "acc-dedupe",
      pollMs: 10,
      signal: controller.signal,
      fetchImpl: mockFetch as typeof fetch,
      homeDir: tempDir,
      onOtp: (otp) => {
        otps.push(otp);
      }
    });

    expect(otps).toHaveLength(1);
    expect(otps[0].code).toBe("456789");
    expect(otps[0].sender).toBe("Google");
  });

  it("html: multipart email with HTML body only results in stripped text and extracted OTP", async () => {
    const store = new TokenStore(tempDir);
    await store.set("acc-html", {
      refreshToken: "refresh-token-html",
      email: "html@example.com",
      addedAt: Date.now()
    });

    const otps: OtpNotification[] = [];
    const controller = new AbortController();

    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/profile")) {
        return new Response(JSON.stringify({ historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/messages?labelIds=")) {
        return new Response(JSON.stringify({ messages: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/history")) {
        return new Response(
          JSON.stringify({
            history: [{ messagesAdded: [{ message: { id: "msg-html-only" } }] }],
            historyId: "101"
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/messages/msg-html-only?format=full")) {
        return new Response(
          JSON.stringify({
            id: "msg-html-only",
            internalDate: String(Date.now()),
            payload: {
              headers: [
                { name: "Subject", value: "Login passcode" },
                { name: "From", value: "Support Team <support@company.org>" }
              ],
              mimeType: "multipart/alternative",
              parts: [
                {
                  mimeType: "text/html",
                  body: {
                    data: Buffer.from(
                      "<html><head><style>p { color: blue; }</style></head><body><p>Use security code <strong>987123</strong> to sign in.</p></body></html>"
                    ).toString("base64url")
                  }
                }
              ]
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not found", { status: 404 });
    };

    await watchAccount({
      accountId: "acc-html",
      pollMs: 10,
      signal: controller.signal,
      fetchImpl: mockFetch as typeof fetch,
      homeDir: tempDir,
      onOtp: (otp) => {
        otps.push(otp);
        controller.abort();
      }
    });

    expect(otps).toHaveLength(1);
    expect(otps[0].code).toBe("987123");
    expect(otps[0].sender).toBe("Support Team");
  });

  it("backoff: 429 and 5xx responses trigger exponential backoff and recovery", async () => {
    const store = new TokenStore(tempDir);
    await store.set("acc-backoff", {
      refreshToken: "refresh-token-backoff",
      email: "backoff@example.com",
      addedAt: Date.now()
    });

    const recordedErrors: string[] = [];
    const controller = new AbortController();
    let attempt = 0;

    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/profile")) {
        return new Response(JSON.stringify({ historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/messages?labelIds=")) {
        return new Response(JSON.stringify({ messages: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/history")) {
        attempt++;
        if (attempt === 1) {
          return new Response("Rate limit exceeded", { status: 429 });
        }
        if (attempt === 2) {
          return new Response("Server error", { status: 503 });
        }
        controller.abort();
        return new Response(JSON.stringify({ history: [], historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      return new Response("Not found", { status: 404 });
    };

    await watchAccount({
      accountId: "acc-backoff",
      pollMs: 5,
      initialBackoffMs: 10,
      maxBackoffMs: 50,
      signal: controller.signal,
      fetchImpl: mockFetch as typeof fetch,
      homeDir: tempDir,
      onOtp: () => {},
      onError: (err) => {
        recordedErrors.push(err.message);
      }
    });

    expect(recordedErrors).toHaveLength(2);
    expect(recordedErrors[0]).toContain("429");
    expect(recordedErrors[1]).toContain("503");
  });

  it("reauth: ReauthRequiredError stops that loop without crashing", async () => {
    const store = new TokenStore(tempDir);
    await store.set("acc-reauth", {
      refreshToken: "bad-refresh-token",
      email: "reauth@example.com",
      addedAt: Date.now()
    });

    let reportedError: Error | null = null;

    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ error: "invalid_grant", error_description: "Token revoked" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not found", { status: 404 });
    };

    await watchAccount({
      accountId: "acc-reauth",
      pollMs: 10,
      fetchImpl: mockFetch as typeof fetch,
      homeDir: tempDir,
      onOtp: () => {},
      onError: (err) => {
        reportedError = err;
      }
    });

    expect(reportedError).toBeInstanceOf(ReauthRequiredError);
  });

  it("abort: signal cleanly terminates the watcher loop", async () => {
    const store = new TokenStore(tempDir);
    await store.set("acc-abort", {
      refreshToken: "refresh-token-abort",
      email: "abort@example.com",
      addedAt: Date.now()
    });

    const controller = new AbortController();
    let pollInvoked = false;

    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/profile")) {
        return new Response(JSON.stringify({ historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/messages?labelIds=")) {
        return new Response(JSON.stringify({ messages: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/history")) {
        pollInvoked = true;
        controller.abort();
        return new Response(JSON.stringify({ history: [], historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      return new Response("Not found", { status: 404 });
    };

    await watchAccount({
      accountId: "acc-abort",
      pollMs: 10,
      signal: controller.signal,
      fetchImpl: mockFetch as typeof fetch,
      homeDir: tempDir,
      onOtp: () => {}
    });

    expect(pollInvoked).toBe(true);
  });

  it("non-OTP email produces no onOtp call", async () => {
    const store = new TokenStore(tempDir);
    await store.set("acc-newsletter", {
      refreshToken: "refresh-token-newsletter",
      email: "newsletter@example.com",
      addedAt: Date.now()
    });

    let onOtpCalled = false;
    const controller = new AbortController();

    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/profile")) {
        return new Response(JSON.stringify({ historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/messages?labelIds=")) {
        return new Response(JSON.stringify({ messages: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/history")) {
        return new Response(
          JSON.stringify({
            history: [{ messagesAdded: [{ message: { id: "msg-newsletter-1" } }] }],
            historyId: "101"
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/messages/msg-newsletter-1?format=full")) {
        controller.abort();
        return new Response(
          JSON.stringify({
            id: "msg-newsletter-1",
            internalDate: String(Date.now()),
            payload: {
              headers: [
                { name: "Subject", value: "Your Weekly Digest" },
                { name: "From", value: "Digest <digest@techsite.com>" }
              ],
              mimeType: "text/plain",
              body: {
                data: Buffer.from("Here is what happened this week in open source software.").toString(
                  "base64url"
                )
              }
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not found", { status: 404 });
    };

    await watchAccount({
      accountId: "acc-newsletter",
      pollMs: 10,
      signal: controller.signal,
      fetchImpl: mockFetch as typeof fetch,
      homeDir: tempDir,
      onOtp: () => {
        onOtpCalled = true;
      }
    });

    expect(onOtpCalled).toBe(false);
  });

  it("abort listener leak regression: 50+ polls maintain at most 2 abort listeners on shared signal and abort stops loop", async () => {
    const store = new TokenStore(tempDir);
    await store.set("acc-listener-leak", {
      refreshToken: "refresh-token-leak",
      email: "leak@example.com",
      addedAt: Date.now()
    });

    const controller = new AbortController();
    const signal = controller.signal;
    let pollCount = 0;
    let maxListenersSeen = 0;

    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "mock-access-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/profile")) {
        return new Response(JSON.stringify({ historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/messages?labelIds=")) {
        return new Response(JSON.stringify({ messages: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/history")) {
        pollCount++;
        const currentListeners = getEventListeners(signal, "abort").length;
        if (currentListeners > maxListenersSeen) {
          maxListenersSeen = currentListeners;
        }
        // Assert throughout the run that listeners stay <= 2
        expect(currentListeners).toBeLessThanOrEqual(2);

        if (pollCount >= 55) {
          controller.abort();
        }

        return new Response(JSON.stringify({ history: [], historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      return new Response("Not found", { status: 404 });
    };

    await watchAccount({
      accountId: "acc-listener-leak",
      pollMs: 1,
      signal,
      fetchImpl: mockFetch as typeof fetch,
      homeDir: tempDir,
      onOtp: () => {}
    });

    expect(pollCount).toBeGreaterThanOrEqual(50);
    expect(maxListenersSeen).toBeLessThanOrEqual(2);
    // After the run, listeners must stay <= 2 (and should be 0)
    expect(getEventListeners(signal, "abort").length).toBeLessThanOrEqual(2);
    expect(signal.aborted).toBe(true);
  });

  it("abort listener limit with N concurrent watchers: shared signal maintains at most N+2 listeners", async () => {
    const N = 4;
    const store = new TokenStore(tempDir);
    for (let i = 1; i <= N; i++) {
      await store.set(`concurrent-${i}`, {
        refreshToken: `token-${i}`,
        email: `conc${i}@example.com`,
        addedAt: Date.now() + i
      });
    }

    const controller = new AbortController();
    const signal = controller.signal;
    let totalPolls = 0;
    let maxListeners = 0;

    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = input.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "mock-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/profile")) {
        return new Response(JSON.stringify({ historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/messages?labelIds=")) {
        return new Response(JSON.stringify({ messages: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (urlStr.includes("/history")) {
        totalPolls++;
        const count = getEventListeners(signal, "abort").length;
        if (count > maxListeners) maxListeners = count;
        expect(count).toBeLessThanOrEqual(N + 2);

        if (totalPolls >= 20) {
          controller.abort();
        }
        return new Response(JSON.stringify({ history: [], historyId: "100" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      return new Response("Not found", { status: 404 });
    };

    await Promise.all(
      Array.from({ length: N }, (_, i) =>
        watchAccount({
          accountId: `concurrent-${i + 1}`,
          pollMs: 1,
          signal,
          fetchImpl: mockFetch as typeof fetch,
          homeDir: tempDir,
          onOtp: () => {}
        })
      )
    );

    expect(maxListeners).toBeLessThanOrEqual(N + 2);
    expect(getEventListeners(signal, "abort").length).toBeLessThanOrEqual(2);
  });

  describe("Fast and Measurable History Polling", () => {
    it("reports a new message once and advances startHistoryId between polls", async () => {
      const store = new TokenStore(tempDir);
      await store.set("acc-hist", {
        refreshToken: "token-hist",
        email: "hist@example.com",
        addedAt: Date.now()
      });

      const controller = new AbortController();
      const requestedUrls: string[] = [];
      const otps: OtpNotification[] = [];
      let historyPollCount = 0;

      const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
        const urlStr = input.toString();
        requestedUrls.push(urlStr);

        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(
            JSON.stringify({ access_token: "mock-token", expires_in: 3600 }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/profile")) {
          return new Response(JSON.stringify({ historyId: "100" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/messages?labelIds=")) {
          return new Response(JSON.stringify({ messages: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/history")) {
          historyPollCount++;
          if (historyPollCount === 1) {
            expect(urlStr).toContain("startHistoryId=100");
            return new Response(
              JSON.stringify({
                history: [
                  {
                    messagesAdded: [{ message: { id: "msg-hist-1" } }]
                  }
                ],
                historyId: "150"
              }),
              { status: 200, headers: { "Content-Type": "application/json" } }
            );
          }
          if (historyPollCount === 2) {
            // startHistoryId must have advanced to 150
            expect(urlStr).toContain("startHistoryId=150");
            controller.abort();
            return new Response(
              JSON.stringify({
                history: [],
                historyId: "150"
              }),
              { status: 200, headers: { "Content-Type": "application/json" } }
            );
          }
        }
        if (urlStr.includes("/messages/msg-hist-1?format=full")) {
          return new Response(
            JSON.stringify({
              id: "msg-hist-1",
              internalDate: String(Date.now()),
              payload: {
                headers: [
                  { name: "Subject", value: "Code" },
                  { name: "From", value: "Service <service@site.com>" }
                ],
                mimeType: "text/plain",
                body: {
                  data: Buffer.from("Your code is 839201.").toString("base64url")
                }
              }
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        return new Response("Not found", { status: 404 });
      };

      await watchAccount({
        accountId: "acc-hist",
        pollMs: 1,
        signal: controller.signal,
        fetchImpl: mockFetch as typeof fetch,
        homeDir: tempDir,
        onOtp: (otp) => {
          otps.push(otp);
        }
      });

      expect(otps).toHaveLength(1);
      expect(otps[0].code).toBe("839201");
      expect(historyPollCount).toBe(2);

      // Verify no URL ever contains "q=" or "after:"
      for (const url of requestedUrls) {
        expect(url).not.toContain("q=");
        expect(url).not.toContain("after:");
      }
    });

    it("follows nextPageToken across history pages", async () => {
      const store = new TokenStore(tempDir);
      await store.set("acc-pages", {
        refreshToken: "token-pages",
        email: "pages@example.com",
        addedAt: Date.now()
      });

      const controller = new AbortController();
      const otps: OtpNotification[] = [];
      const historyUrls: string[] = [];

      const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
        const urlStr = input.toString();
        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(
            JSON.stringify({ access_token: "mock-token", expires_in: 3600 }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/profile")) {
          return new Response(JSON.stringify({ historyId: "200" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/messages?labelIds=")) {
          return new Response(JSON.stringify({ messages: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/history")) {
          historyUrls.push(urlStr);
          if (!urlStr.includes("pageToken=")) {
            return new Response(
              JSON.stringify({
                history: [{ messagesAdded: [{ message: { id: "msg-p1" } }] }],
                nextPageToken: "page-2-token",
                historyId: "205"
              }),
              { status: 200, headers: { "Content-Type": "application/json" } }
            );
          }
          if (urlStr.includes("pageToken=page-2-token")) {
            return new Response(
              JSON.stringify({
                history: [{ messagesAdded: [{ message: { id: "msg-p2" } }] }],
                historyId: "210"
              }),
              { status: 200, headers: { "Content-Type": "application/json" } }
            );
          }
          return new Response(JSON.stringify({ history: [], historyId: "210" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/messages/msg-p1?format=full")) {
          return new Response(
            JSON.stringify({
              id: "msg-p1",
              internalDate: String(Date.now()),
              payload: {
                headers: [
                  { name: "Subject", value: "Code" },
                  { name: "From", value: "A <a@a.com>" }
                ],
                mimeType: "text/plain",
                body: { data: Buffer.from("Your code is 111222.").toString("base64url") }
              }
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/messages/msg-p2?format=full")) {
          return new Response(
            JSON.stringify({
              id: "msg-p2",
              internalDate: String(Date.now()),
              payload: {
                headers: [
                  { name: "Subject", value: "Code" },
                  { name: "From", value: "B <b@b.com>" }
                ],
                mimeType: "text/plain",
                body: { data: Buffer.from("Your code is 333444.").toString("base64url") }
              }
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        return new Response("Not found", { status: 404 });
      };

      await watchAccount({
        accountId: "acc-pages",
        pollMs: 1,
        signal: controller.signal,
        fetchImpl: mockFetch as typeof fetch,
        homeDir: tempDir,
        onOtp: (otp) => {
          otps.push(otp);
          if (otps.length >= 2) {
            controller.abort();
          }
        }
      });

      expect(otps).toHaveLength(2);
      expect(otps.map((o) => o.code)).toEqual(["111222", "333444"]);
      expect(historyUrls.some((u) => u.includes("pageToken=page-2-token"))).toBe(true);
    });

    it("triggers recovery path on 404 and continues polling", async () => {
      const store = new TokenStore(tempDir);
      await store.set("acc-404", {
        refreshToken: "token-404",
        email: "recovered@example.com",
        addedAt: Date.now()
      });

      const controller = new AbortController();
      let profileCallCount = 0;
      let recoveryListCount = 0;
      const otps: OtpNotification[] = [];

      const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
        const urlStr = input.toString();
        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(
            JSON.stringify({ access_token: "mock-token", expires_in: 3600 }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/profile")) {
          profileCallCount++;
          const hid = profileCallCount === 1 ? "100" : "500";
          return new Response(JSON.stringify({ historyId: hid }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/messages?labelIds=")) {
          recoveryListCount++;
          if (recoveryListCount === 1) {
            // Initial startup
            return new Response(JSON.stringify({ messages: [] }), {
              status: 200,
              headers: { "Content-Type": "application/json" }
            });
          }
          // Recovery list after 404: find recent message
          return new Response(
            JSON.stringify({ messages: [{ id: "msg-recovered" }] }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/history")) {
          if (urlStr.includes("startHistoryId=100")) {
            // First poll: simulate history expired
            return new Response("History expired", { status: 404 });
          }
          return new Response(
            JSON.stringify({ history: [], historyId: "500" }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/messages/msg-recovered?format=full")) {
          return new Response(
            JSON.stringify({
              id: "msg-recovered",
              internalDate: String(Date.now() - 5000), // 5 seconds ago -> within 60s
              payload: {
                headers: [
                  { name: "Subject", value: "Verification code" },
                  { name: "From", value: "Recovery <rec@example.com>" }
                ],
                mimeType: "text/plain",
                body: { data: Buffer.from("Your OTP is 776655").toString("base64url") }
              }
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        return new Response("Not found", { status: 404 });
      };

      await watchAccount({
        accountId: "acc-404",
        pollMs: 1,
        signal: controller.signal,
        fetchImpl: mockFetch as typeof fetch,
        homeDir: tempDir,
        onOtp: (otp) => {
          otps.push(otp);
          controller.abort();
        }
      });

      expect(profileCallCount).toBeGreaterThanOrEqual(2);
      expect(recoveryListCount).toBeGreaterThanOrEqual(2);
      expect(otps).toHaveLength(1);
      expect(otps[0].code).toBe("776655");
    });

    it("prints latency line only when AUTOOTP_DEBUG=timing and never includes digits of the code", async () => {
      const store = new TokenStore(tempDir);
      await store.set("acc-timing", {
        refreshToken: "token-timing",
        email: "timing@example.com",
        addedAt: Date.now()
      });

      const otpCode = "948271";
      let pollIndex = 0;

      const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
        const urlStr = input.toString();
        if (urlStr.includes("oauth2.googleapis.com/token")) {
          return new Response(
            JSON.stringify({ access_token: "mock-token", expires_in: 3600 }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/profile")) {
          return new Response(JSON.stringify({ historyId: "100" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/messages?labelIds=")) {
          return new Response(JSON.stringify({ messages: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (urlStr.includes("/history")) {
          pollIndex++;
          return new Response(
            JSON.stringify({
              history: [{ messagesAdded: [{ message: { id: `msg-timed-${pollIndex}` } }] }],
              historyId: "105"
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (urlStr.includes("/messages/msg-timed-")) {
          return new Response(
            JSON.stringify({
              id: "msg-timed",
              internalDate: String(Date.now() - 320),
              payload: {
                headers: [
                  { name: "Subject", value: "Code" },
                  { name: "From", value: "Sec <sec@test.com>" }
                ],
                mimeType: "text/plain",
                body: { data: Buffer.from(`Your code is ${otpCode}.`).toString("base64url") }
              }
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        return new Response("Not found", { status: 404 });
      };

      // 1. Without AUTOOTP_DEBUG
      delete process.env.AUTOOTP_DEBUG;
      const controller1 = new AbortController();
      const stderrLinesNoDebug: string[] = [];
      const origErr = console.error;
      console.error = (msg: string) => stderrLinesNoDebug.push(msg);

      try {
        await watchAccount({
          accountId: "acc-timing",
          pollMs: 1,
          signal: controller1.signal,
          fetchImpl: mockFetch as typeof fetch,
          homeDir: tempDir,
          onOtp: () => {
            controller1.abort();
          }
        });
      } finally {
        console.error = origErr;
      }

      expect(stderrLinesNoDebug.some((l) => l.includes("latency:"))).toBe(false);

      // 2. With AUTOOTP_DEBUG=timing
      process.env.AUTOOTP_DEBUG = "timing";
      const controller2 = new AbortController();
      const stderrLinesTiming: string[] = [];
      console.error = (msg: string) => stderrLinesTiming.push(msg);

      try {
        await watchAccount({
          accountId: "acc-timing",
          pollMs: 1,
          signal: controller2.signal,
          fetchImpl: mockFetch as typeof fetch,
          homeDir: tempDir,
          onOtp: () => {
            controller2.abort();
          }
        });
      } finally {
        delete process.env.AUTOOTP_DEBUG;
        console.error = origErr;
      }

      const latencyLine = stderrLinesTiming.find((l) => l.startsWith("latency:"));
      expect(latencyLine).toBeTruthy();
      expect(latencyLine).toMatch(/^latency: \d+ ms \(received to detected\)$/);
      // Prove no digits of the code appear in the latency line
      expect(latencyLine).not.toContain(otpCode);
      for (let i = 0; i <= otpCode.length - 2; i++) {
        expect(latencyLine).not.toContain(otpCode.slice(i, i + 2));
      }
    });
  });

  describe("isSenderVerified", () => {
    const ok =
      "mx.google.com; dkim=pass header.i=@github.com; spf=pass smtp.mailfrom=noreply@github.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com";
    const H = (v: string) => [{ name: "Authentication-Results", value: v }];

    it("verifies aligned dmarc pass with mx.google.com", () => {
      expect(isSenderVerified(H(ok), "github.com")).toBe(true);
    });

    it("returns false if senderDomain is null or empty", () => {
      expect(isSenderVerified(H(ok), null)).toBe(false);
      expect(isSenderVerified(H(ok), "")).toBe(false);
      expect(isSenderVerified(H(ok), "   ")).toBe(false);
    });

    it("returns false if there is more than one From header", () => {
      const headers = [
        { name: "From", value: "support@github.com" },
        { name: "From", value: "attacker@evil.com" },
        { name: "Authentication-Results", value: ok }
      ];
      expect(isSenderVerified(headers, "github.com")).toBe(false);
    });

    it("accepts a single From header", () => {
      const headers = [
        { name: "From", value: "support@github.com" },
        { name: "Authentication-Results", value: ok }
      ];
      expect(isSenderVerified(headers, "github.com")).toBe(true);
    });

    it("returns false if there is no Authentication-Results header", () => {
      const headers = [{ name: "From", value: "support@github.com" }];
      expect(isSenderVerified(headers, "github.com")).toBe(false);
    });

    it("returns false if first token before first ';' does not equal mx.google.com", () => {
      expect(
        isSenderVerified(
          H("evil.example; dmarc=pass header.from=github.com"),
          "github.com"
        )
      ).toBe(false);
      expect(
        isSenderVerified(
          H("mx.google.com.attacker.com; dmarc=pass header.from=github.com"),
          "github.com"
        )
      ).toBe(false);
    });

    it("uses only the FIRST Authentication-Results header in message order", () => {
      // 1st fails, 2nd passes -> must be false
      const forgedLower = [
        {
          name: "Authentication-Results",
          value: "mx.google.com; dmarc=fail header.from=github.com"
        },
        { name: "Authentication-Results", value: ok }
      ];
      expect(isSenderVerified(forgedLower, "github.com")).toBe(false);

      // 1st passes, 2nd fails -> must be true
      const forgedHigher = [
        { name: "Authentication-Results", value: ok },
        {
          name: "Authentication-Results",
          value: "mx.google.com; dmarc=fail header.from=github.com"
        }
      ];
      expect(isSenderVerified(forgedHigher, "github.com")).toBe(true);
    });

    it("removes parenthetical comments (including nested ones) BEFORE parsing", () => {
      // Comment spoofing attempt
      const commentSpoof = H(
        "mx.google.com; spf=pass (google.com: note dmarc=pass header.from=github.com); dmarc=fail header.from=github.com"
      );
      expect(isSenderVerified(commentSpoof, "github.com")).toBe(false);

      // Nested comments inside passing dmarc
      const nestedComments = H(
        "mx.google.com; dmarc=pass (nested (double (triple) note)) header.from=github.com"
      );
      expect(isSenderVerified(nestedComments, "github.com")).toBe(true);

      // Malformed comments (unmatched opening paren)
      const unclosedComment = H(
        "mx.google.com; dmarc=pass (unclosed header.from=github.com"
      );
      expect(isSenderVerified(unclosedComment, "github.com")).toBe(false);
    });

    it("is case-insensitive for mx.google.com, method, result, header.from, and senderDomain", () => {
      const mixedCase = H(
        "MX.GOOGLE.COM; DMARC=PASS (dis=NONE) HEADER.FROM=GitHub.Com"
      );
      expect(isSenderVerified(mixedCase, "github.com")).toBe(true);
      expect(isSenderVerified(mixedCase, "GITHUB.COM")).toBe(true);
      expect(isSenderVerified(mixedCase, "GitHub.com")).toBe(true);
    });

    it("accepts quoted header.from", () => {
      const quoted = H(
        'mx.google.com; dmarc=pass header.from="github.com"'
      );
      expect(isSenderVerified(quoted, "github.com")).toBe(true);
    });

    it("returns false when dmarc fails or is not pass", () => {
      expect(
        isSenderVerified(
          H("mx.google.com; dmarc=fail header.from=github.com"),
          "github.com"
        )
      ).toBe(false);
      expect(
        isSenderVerified(
          H("mx.google.com; dmarc=none header.from=github.com"),
          "github.com"
        )
      ).toBe(false);
      expect(
        isSenderVerified(
          H("mx.google.com; dmarc=temperror header.from=github.com"),
          "github.com"
        )
      ).toBe(false);
    });

    it("returns false when header.from mismatches senderDomain", () => {
      expect(
        isSenderVerified(
          H("mx.google.com; dmarc=pass header.from=evil.com"),
          "github.com"
        )
      ).toBe(false);
    });

    it("returns false when dmarc segment is missing header.from", () => {
      expect(
        isSenderVerified(
          H("mx.google.com; dmarc=pass"),
          "github.com"
        )
      ).toBe(false);
    });

    it("returns false when a segment is malformed (no method=result)", () => {
      expect(
        isSenderVerified(
          H("mx.google.com; malformed-segment-without-equals; dmarc=pass header.from=github.com"),
          "github.com"
        )
      ).toBe(false);
    });

    it("watcher adds senderVerified boolean to every OTP notification it emits", async () => {
      const store = new TokenStore(tempDir);
      await store.set("acc-verified-test", {
        refreshToken: "token-verified",
        email: "verified@example.com",
        addedAt: Date.now()
      });

      let receivedOtp: OtpNotification | undefined;
      const controller = new AbortController();

      const mockFetch = async (input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.includes("oauth2.googleapis.com/token")) {
          return new Response(
            JSON.stringify({ access_token: "mock-token", expires_in: 3600 }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (url.includes("/profile")) {
          return new Response(JSON.stringify({ historyId: "100" }), { status: 200 });
        }
        if (url.includes("/messages?labelIds=")) {
          return new Response(JSON.stringify({ messages: [{ id: "m-verified" }] }), { status: 200 });
        }
        if (url.includes("/messages/m-verified")) {
          return new Response(
            JSON.stringify({
              id: "m-verified",
              internalDate: String(Date.now()),
              payload: {
                headers: [
                  { name: "From", value: "GitHub <noreply@github.com>" },
                  { name: "Subject", value: "Your verification code" },
                  { name: "Authentication-Results", value: ok }
                ],
                body: { data: Buffer.from("Here is your OTP code: 849201").toString("base64url") },
                mimeType: "text/plain"
              }
            }),
            { status: 200 }
          );
        }
        return new Response("{}", { status: 200 });
      };

      await watchAccount({
        accountId: "acc-verified-test",
        pollMs: 1,
        signal: controller.signal,
        fetchImpl: mockFetch as typeof fetch,
        homeDir: tempDir,
        onOtp: (otp) => {
          receivedOtp = otp;
          controller.abort();
        }
      });

      expect(receivedOtp).toBeTruthy();
      expect(receivedOtp?.senderVerified).toBe(true);
      expect(typeof receivedOtp?.senderVerified).toBe("boolean");
    });
  });
});

