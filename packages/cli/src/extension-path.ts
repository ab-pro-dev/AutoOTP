import fs from "node:fs";
import path from "node:path";
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
