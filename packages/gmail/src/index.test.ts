import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { TokenStore } from "@autootp/shared";
import {
  createVerifier,
  createChallenge,
  createState,
  loadCredentials,
  loginWithBrowser,
  refreshAccessToken,
  ReauthRequiredError
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
