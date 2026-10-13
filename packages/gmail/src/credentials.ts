import fs from "node:fs";
import path from "node:path";
import { getHomeDir } from "@autootp/shared";

export interface GoogleInstalledCredentials {
  client_id: string;
  client_secret: string;
  redirect_uris?: string[];
  auth_uri?: string;
  token_uri?: string;
  [key: string]: unknown;
}

export interface GoogleCredentialsFile {
  installed?: GoogleInstalledCredentials;
  web?: unknown;
  [key: string]: unknown;
}

export interface OAuthCredentials {
  clientId: string;
  clientSecret: string;
}

/**
 * Loads OAuth client credentials from <home>/credentials.json.
 * Expects Google "Desktop app" credentials format with an "installed" key.
 */
export function loadCredentials(homeDir: string = getHomeDir()): OAuthCredentials {
  const credentialsPath = path.join(homeDir, "credentials.json");

  if (!fs.existsSync(credentialsPath)) {
    throw new Error(
      `OAuth client credentials file not found at ${credentialsPath}. ` +
      `Please download your OAuth client JSON from Google Cloud Console and save it to that path.`
    );
  }

  let raw: string;
  try {
    raw = fs.readFileSync(credentialsPath, "utf8");
  } catch (err: unknown) {
    throw new Error(`Failed to read credentials file at ${credentialsPath}: ${(err as Error).message}`);
  }

  let data: GoogleCredentialsFile;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON in credentials file at ${credentialsPath}`);
  }

  if (data.web) {
    throw new Error(
      `Invalid credentials format in ${credentialsPath}: found "web" client type. ` +
      `Please download a "Desktop app" OAuth client credentials JSON.`
    );
  }

  if (!data.installed || typeof data.installed !== "object") {
    throw new Error(
      `Invalid credentials format in ${credentialsPath}: missing "installed" key. ` +
      `Expected Google Desktop app credentials JSON.`
    );
  }

  const { client_id, client_secret } = data.installed;

  if (!client_id || typeof client_id !== "string" || !client_secret || typeof client_secret !== "string") {
    throw new Error(
      `Invalid credentials in ${credentialsPath}: "installed" object must contain "client_id" and "client_secret".`
    );
  }

  return {
    clientId: client_id,
    clientSecret: client_secret
  };
}
