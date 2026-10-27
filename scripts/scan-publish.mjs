import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const FORBIDDEN_VALUE_PATTERNS = [
  /GOCSPX-[A-Za-z0-9_-]{20,}/,
  /ya29\.[A-Za-z0-9_-]{20,}/,
  /1\/\/[A-Za-z0-9_-]{20,}/,
  /ghp_[A-Za-z0-9]{20,}/,
  /AIza[A-Za-z0-9_-]{30,}/,
  /BEGIN (RSA |EC )?PRIVATE KEY/,
  /apps\.googleusercontent\.com/,
  /332568239211/
];

export function isForbiddenFilename(name) {
  if (name.endsWith(".pem")) return true;
  if (name.endsWith(".enc")) return true;
  if (name.endsWith(".db")) return true;
  if (name.startsWith(".env")) return true;
  if (name.startsWith("credentials") && name.endsWith(".json")) return true;
  return false;
}

export function scanDirectory(dir, root = dir) {
  const violations = [];
  if (!fs.existsSync(dir)) {
    violations.push({ file: dir, reason: "Directory does not exist" });
    return { ok: false, violations };
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(root, fullPath);

    if (isForbiddenFilename(entry.name)) {
      violations.push({
        file: relPath,
        reason: `Forbidden file name: "${entry.name}"`
      });
    }

    if (entry.isDirectory()) {
      const sub = scanDirectory(fullPath, root);
      violations.push(...sub.violations);
    } else if (entry.isFile()) {
      try {
        const content = fs.readFileSync(fullPath, "utf8");
        for (const pattern of FORBIDDEN_VALUE_PATTERNS) {
          if (pattern.test(content)) {
            violations.push({
              file: relPath,
              reason: `Matched secret value pattern: ${pattern.source}`
            });
          }
        }
      } catch {
        // Ignore unreadable files
      }
    }
  }

  return {
    ok: violations.length === 0,
    violations
  };
}

export async function runScan(targetDir) {
  const rootDir = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const dir = targetDir || path.join(rootDir, "publish");

  const result = scanDirectory(dir);
  if (!result.ok) {
    console.error(`Secret scan FAILED for ${path.relative(rootDir, dir) || dir}:`);
    for (const v of result.violations) {
      console.error(`  - ${v.file}: ${v.reason}`);
    }
    return false;
  }

  return true;
}

if (process.argv[1] && (import.meta.url === pathToFileURL(process.argv[1]).href || process.argv[1].endsWith("scan-publish.mjs"))) {
  const targetDir = process.argv[2];
  const ok = await runScan(targetDir);
  if (!ok) {
    process.exit(1);
  }
}
