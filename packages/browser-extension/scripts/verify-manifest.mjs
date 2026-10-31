import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Extracts all relative file paths referenced in a Chrome extension manifest.
 * @param {Record<string, unknown>} manifest
 * @returns {string[]}
 */
export function getReferencedFiles(manifest) {
  const files = [];

  // 1. icons
  if (manifest.icons && typeof manifest.icons === "object") {
    for (const val of Object.values(manifest.icons)) {
      if (typeof val === "string" && val.trim().length > 0) {
        files.push(val.trim());
      }
    }
  }

  // 2. action.default_icon
  const action = /** @type {Record<string, unknown> | undefined} */ (manifest.action);
  if (action?.default_icon) {
    if (typeof action.default_icon === "string" && action.default_icon.trim().length > 0) {
      files.push(action.default_icon.trim());
    } else if (typeof action.default_icon === "object") {
      for (const val of Object.values(action.default_icon)) {
        if (typeof val === "string" && val.trim().length > 0) {
          files.push(val.trim());
        }
      }
    }
  }

  // 3. action.default_popup
  if (typeof action?.default_popup === "string" && action.default_popup.trim().length > 0) {
    files.push(action.default_popup.trim());
  }

  // 4. background.service_worker
  const bg = /** @type {Record<string, unknown> | undefined} */ (manifest.background);
  if (typeof bg?.service_worker === "string" && bg.service_worker.trim().length > 0) {
    files.push(bg.service_worker.trim());
  }

  // 5. content_scripts[].js and content_scripts[].css
  if (Array.isArray(manifest.content_scripts)) {
    for (const entry of manifest.content_scripts) {
      if (entry && typeof entry === "object") {
        if (Array.isArray(entry.js)) {
          for (const js of entry.js) {
            if (typeof js === "string" && js.trim().length > 0) {
              files.push(js.trim());
            }
          }
        }
        if (Array.isArray(entry.css)) {
          for (const css of entry.css) {
            if (typeof css === "string" && css.trim().length > 0) {
              files.push(css.trim());
            }
          }
        }
      }
    }
  }

  // 6. web_accessible_resources
  if (Array.isArray(manifest.web_accessible_resources)) {
    for (const entry of manifest.web_accessible_resources) {
      if (entry && typeof entry === "object" && Array.isArray(entry.resources)) {
        for (const r of entry.resources) {
          if (typeof r === "string" && r.trim().length > 0 && !r.includes("*")) {
            files.push(r.trim());
          }
        }
      }
    }
  }

  return Array.from(new Set(files));
}

/**
 * Verifies that all files referenced in an extension directory's manifest.json exist on disk.
 * Fails with a clear error listing any missing files.
 * @param {string} dir - Directory containing manifest.json and referenced files.
 * @returns {string[]} List of verified file relative paths.
 */
export function verifyManifestFiles(dir) {
  const manifestPath = path.join(dir, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`Extension manifest.json is missing in ${dir}`);
  }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (err) {
    throw new Error(`Failed to parse manifest.json in ${dir}: ${err.message}`);
  }

  const files = getReferencedFiles(manifest);
  const missing = [];

  for (const relPath of files) {
    const fullPath = path.join(dir, relPath);
    if (!fs.existsSync(fullPath)) {
      missing.push(relPath);
    }
  }

  if (missing.length > 0) {
    const err = new Error(
      `Extension manifest in ${dir} references missing files:\n  - ${missing.join("\n  - ")}`
    );
    err.missingFiles = missing;
    throw err;
  }

  return files;
}

/**
 * Checks whether a module specifier is a bare / non-relative, non-builtin specifier.
 * Relative specifiers (./, ../, /), URLs (http:, https:, data:), and node built-ins (node:) are not bare.
 * Everything else (including @autootp/...) is considered bare.
 * @param {string} specifier
 * @returns {boolean}
 */
export function isBareSpecifier(specifier) {
  if (!specifier || typeof specifier !== "string") return false;
  const s = specifier.trim();
  if (s.startsWith("./") || s.startsWith("../") || s.startsWith("/")) return false;
  if (s.startsWith("http://") || s.startsWith("https://") || s.startsWith("data:")) return false;
  if (s.startsWith("node:")) return false;
  return true;
}

/**
 * Scans a file's content for import/require of bare or non-relative module specifiers.
 * @param {string} filePath
 * @param {string} [content]
 * @returns {Array<{ file: string, line: number, specifier: string, lineContent: string }>}
 */
export function scanFileForBareSpecifiers(filePath, content) {
  const code = content !== undefined ? content : fs.readFileSync(filePath, "utf8");
  const violations = [];
  const lines = code.split("\n");

  const patterns = [
    /\b(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
    /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g
  ];

  for (const regex of patterns) {
    let match;
    while ((match = regex.exec(code)) !== null) {
      const specifier = match[1];
      if (isBareSpecifier(specifier)) {
        const line = code.substring(0, match.index).split("\n").length;
        const lineContent = lines[line - 1] ? lines[line - 1].trim() : "";
        violations.push({
          file: filePath,
          line,
          specifier,
          lineContent
        });
      }
    }
  }

  violations.sort((a, b) => a.line - b.line);
  return violations;
}

/**
 * Scans every *.js file in the directory for bare or non-relative specifiers.
 * Fails with a clear error listing the offending file, line, and specifier.
 * @param {string} dir
 * @returns {string[]} List of scanned *.js files
 */
export function verifyNoBareSpecifiers(dir) {
  if (!fs.existsSync(dir)) {
    throw new Error(`Directory does not exist: ${dir}`);
  }

  const entries = fs.readdirSync(dir);
  const jsFiles = entries.filter((f) => f.endsWith(".js"));
  const violations = [];

  for (const f of jsFiles) {
    const full = path.join(dir, f);
    const fileViolations = scanFileForBareSpecifiers(f, fs.readFileSync(full, "utf8"));
    violations.push(...fileViolations);
  }

  if (violations.length > 0) {
    const details = violations
      .map((v) => `  - ${v.file}:${v.line} imports bare specifier "${v.specifier}" -> ${v.lineContent}`)
      .join("\n");
    throw new Error(
      `Found bare or non-relative module specifier(s) in ${dir}:\n${details}`
    );
  }

  return jsFiles;
}

// Standalone execution
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const targetDir = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve(__dirname, "../dist-ext");

  try {
    const verifiedManifest = verifyManifestFiles(targetDir);
    console.log(`Manifest verified: all ${verifiedManifest.length} referenced files exist in ${targetDir}`);

    const verifiedJs = verifyNoBareSpecifiers(targetDir);
    console.log(`Bundle verified: all ${verifiedJs.length} .js files in ${targetDir} contain zero bare specifiers`);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
