import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import type { CommandContext } from "./commands.js";

/**
 * Resolves the absolute path of the extension directory.
 * First checks for the bundled extension/ folder next to the running file,
 * falling back to packages/browser-extension/dist-ext when run from the source tree.
 * Throws an Error if the directory or manifest.json is missing.
 */
export function resolveExtensionPath(baseUrl: string | URL = import.meta.url): string {
  let currentPath: string;
  if (typeof baseUrl === "string") {
    currentPath = baseUrl.startsWith("file://") ? fileURLToPath(baseUrl) : baseUrl;
  } else if (baseUrl instanceof URL) {
    currentPath = fileURLToPath(baseUrl);
  } else {
    currentPath = String(baseUrl);
  }

  try {
    currentPath = fs.realpathSync(currentPath);
  } catch {
    // Keep currentPath if realpathSync fails
  }

  let currentDir: string;
  try {
    const stat = fs.statSync(currentPath);
    currentDir = stat.isDirectory() ? currentPath : path.dirname(currentPath);
  } catch {
    currentDir = path.dirname(currentPath);
  }

  const candidates = [
    path.resolve(currentDir, "extension"),
    path.resolve(currentDir, "../../browser-extension/dist-ext"),
    path.resolve(currentDir, "../browser-extension/dist-ext"),
    path.resolve(currentDir, "../packages/browser-extension/dist-ext"),
    path.resolve(currentDir, "packages/browser-extension/dist-ext")
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      const manifestPath = path.join(candidate, "manifest.json");
      if (fs.existsSync(manifestPath)) {
        return candidate;
      }
      throw new Error(`Extension manifest.json is missing in ${candidate}`);
    }
  }

  throw new Error("Extension directory not found");
}

export async function extensionPathAction(context: CommandContext = {}): Promise<void> {
  const exit = context.exitImpl ?? process.exit;
  try {
    const extPath = resolveExtensionPath(context.metaUrl ?? import.meta.url);
    console.log(extPath);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(message);
    exit(1);
  }
}

/**
 * Computes the Chrome extension ID from the base64-encoded public key in manifest.json.
 * (SHA-256 of the DER public key, first 32 hex characters mapped 0-9a-f to a-p).
 */
export function computeExtensionIdFromKey(key: string): string {
  const der = Buffer.from(key, "base64");
  const hash = crypto.createHash("sha256").update(der).digest("hex");
  return hash
    .slice(0, 32)
    .split("")
    .map((c) => {
      const val = parseInt(c, 16);
      return String.fromCharCode("a".charCodeAt(0) + val);
    })
    .join("");
}

/**
 * Reads manifest.json from the extension directory and computes the extension ID.
 */
export function getExtensionId(baseUrl?: string | URL): string {
  const extDir = resolveExtensionPath(baseUrl);
  const manifestPath = path.join(extDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`Extension manifest.json is missing in ${extDir}`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (!manifest.key || typeof manifest.key !== "string") {
    throw new Error(`No "key" found in ${manifestPath}`);
  }
  return computeExtensionIdFromKey(manifest.key);
}

export async function extensionIdAction(context: CommandContext = {}): Promise<void> {
  const exit = context.exitImpl ?? process.exit;
  try {
    const id = getExtensionId(context.metaUrl ?? import.meta.url);
    console.log(id);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(message);
    exit(1);
  }
}

