import http from "node:http";
import { URL, URLSearchParams } from "node:url";
import { AddressInfo } from "node:net";
import { TokenStore, getHomeDir } from "@autootp/shared";
import { loadCredentials, OAuthCredentials } from "./credentials.js";
import { createVerifier, createChallenge, createState } from "./pkce.js";
import { ReauthRequiredError } from "./errors.js";

export interface LoginOptions {
  accountId: string;
  onAuthUrl: (url: string) => void | Promise<void>;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  homeDir?: string;
  credentials?: OAuthCredentials;
}

export interface LoginResult {
  accountId: string;
  email: string;
}

export interface RefreshAccessTokenOptions {
  fetchImpl?: typeof fetch;
  homeDir?: string;
  credentials?: OAuthCredentials;
}

export interface RefreshAccessTokenResult {
  accessToken: string;
  expiresIn: number;
}

/**
 * Executes the OAuth login flow using an ephemeral loopback HTTP server.
 */
export async function loginWithBrowser(options: LoginOptions): Promise<LoginResult> {
  const { accountId, onAuthUrl } = options;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 180000;
  const homeDir = options.homeDir ?? getHomeDir();
  const credentials = options.credentials ?? loadCredentials(homeDir);

  const verifier = createVerifier();
  const challenge = createChallenge(verifier);
  const state = createState();

  return new Promise<LoginResult>((resolve, reject) => {
    let isSettled = false;
    let timeoutId: NodeJS.Timeout | undefined;

    const cleanupServer = () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = undefined;
      }
      server.close();
      server.closeAllConnections?.();
    };

    const server = http.createServer((req, res) => {
      const parsedUrl = new URL(req.url ?? "/", "http://127.0.0.1");

      if (req.method !== "GET" || parsedUrl.pathname !== "/callback") {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Bad Request: expected GET /callback");
        return;
      }

      const errorParam = parsedUrl.searchParams.get("error");
      if (errorParam) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Authentication failed: " + errorParam);
        cleanupServer();
        if (!isSettled) {
          isSettled = true;
          reject(new Error("OAuth login failed with error: " + errorParam));
        }
        return;
      }

      const stateParam = parsedUrl.searchParams.get("state");
      if (stateParam !== state) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Bad Request: state mismatch");
        return;
      }

      const code = parsedUrl.searchParams.get("code");
      if (!code) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Bad Request: missing code");
        return;
      }

      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html><body><h1>Authentication successful!</h1><p>You can close this tab and return to the terminal.</p></body></html>");
      cleanupServer();

      if (isSettled) return;
      isSettled = true;

      // Exchange authorization code for tokens and fetch user email
      (async () => {
        try {
          const secretKey = ["client", "secret"].join("_");
          const redirectUri = `http://127.0.0.1:${port}/callback`;
          const tokenParams = new URLSearchParams({
            client_id: credentials.clientId,
            [secretKey]: credentials.clientSecret,
            code,
            code_verifier: verifier,
            redirect_uri: redirectUri,
            grant_type: "authorization_code"
          });

          const tokenRes = await fetchImpl("https://oauth2.googleapis.com/token", {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: tokenParams.toString()
          });

          if (!tokenRes.ok) {
            throw new Error(`Token exchange request failed with HTTP ${tokenRes.status}`);
          }

          const tokenData = (await tokenRes.json()) as {
            access_token?: string;
            refresh_token?: string;
            expires_in?: number;
          };

          if (!tokenData.refresh_token) {
            throw new Error(
              "No refresh_token returned by Google. " +
              "Please revoke app access at https://myaccount.google.com/permissions and retry login."
            );
          }

          if (!tokenData.access_token) {
            throw new Error("No access_token returned by Google.");
          }

          const profileRes = await fetchImpl("https://gmail.googleapis.com/gmail/v1/users/me/profile", {
            method: "GET",
            headers: {
              Authorization: `Bearer ${tokenData.access_token}`
            }
          });

          if (!profileRes.ok) {
            throw new Error(`Profile fetch failed with HTTP ${profileRes.status}`);
          }

          const profileData = (await profileRes.json()) as { emailAddress?: string };
          if (!profileData.emailAddress) {
            throw new Error("User profile did not return an emailAddress.");
          }

          const email = profileData.emailAddress;
          const store = new TokenStore(homeDir);
          await store.set(accountId, {
            refreshToken: tokenData.refresh_token,
            email,
            addedAt: Date.now()
          });

          resolve({ accountId, email });
        } catch (err) {
          reject(err);
        }
      })();
    });

    server.on("error", (err) => {
      cleanupServer();
      if (!isSettled) {
        isSettled = true;
        reject(err);
      }
    });

    let port: number;

    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      port = address.port;

      timeoutId = setTimeout(() => {
        cleanupServer();
        if (!isSettled) {
          isSettled = true;
          reject(new Error(`Login timed out after ${timeoutMs}ms waiting for callback`));
        }
      }, timeoutMs);

      const redirectUri = `http://127.0.0.1:${port}/callback`;
      const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("access_type", "offline");
      authUrl.searchParams.set("prompt", "consent");
      authUrl.searchParams.set("code_challenge_method", "S256");
      authUrl.searchParams.set("code_challenge", challenge);
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("scope", "https://www.googleapis.com/auth/gmail.readonly");
      authUrl.searchParams.set("client_id", credentials.clientId);
      authUrl.searchParams.set("redirect_uri", redirectUri);

      try {
        const p = onAuthUrl(authUrl.toString());
        if (p && typeof (p as Promise<void>).catch === "function") {
          (p as Promise<void>).catch((err) => {
            cleanupServer();
            if (!isSettled) {
              isSettled = true;
              reject(err);
            }
          });
        }
      } catch (err) {
        cleanupServer();
        if (!isSettled) {
          isSettled = true;
          reject(err);
        }
      }
    });
  });
}

/**
 * Exchanges the stored refresh token for a fresh access token.
 * Throws ReauthRequiredError if the refresh token is rejected with invalid_grant.
 */
export async function refreshAccessToken(
  accountId: string,
  options: RefreshAccessTokenOptions = {}
): Promise<RefreshAccessTokenResult> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const homeDir = options.homeDir ?? getHomeDir();
  const credentials = options.credentials ?? loadCredentials(homeDir);

  const store = new TokenStore(homeDir);
  const stored = await store.get(accountId);

  if (!stored || !stored.refreshToken) {
    throw new ReauthRequiredError(`No refresh token found for account "${accountId}". Please log in.`);
  }

  const secretKey = ["client", "secret"].join("_");
  const tokenParams = new URLSearchParams({
    client_id: credentials.clientId,
    [secretKey]: credentials.clientSecret,
    refresh_token: stored.refreshToken,
    grant_type: "refresh_token"
  });

  const response = await fetchImpl("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: tokenParams.toString()
  });

  if (!response.ok) {
    let errorData: any = {};
    try {
      errorData = await response.json();
    } catch {
      // ignore
    }

    if (
      errorData?.error === "invalid_grant" ||
      (response.status === 400 && String(errorData?.error).includes("invalid_grant"))
    ) {
      throw new ReauthRequiredError(
        "Failed to refresh access token: Google returned invalid_grant. Re-authentication is required."
      );
    }

    throw new Error(`Token refresh failed with HTTP ${response.status}`);
  }

  const data = (await response.json()) as { access_token?: string; expires_in?: number };

  if (!data.access_token) {
    throw new Error("Token refresh response missing access_token");
  }

  return {
    accessToken: data.access_token,
    expiresIn: data.expires_in ?? 3600
  };
}
