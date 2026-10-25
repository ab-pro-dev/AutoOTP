import { MULTI_PART_PUBLIC_SUFFIXES } from "@autootp/shared";

export interface HeaderItem {
  name: string;
  value: string;
}

/**
 * Strips RFC 5322 parenthetical comments, including nested ones.
 * Returns { text, malformed: boolean }.
 */
export function stripParentheticalComments(input: string): { text: string; malformed: boolean } {
  let result = "";
  let depth = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (char === "(") {
      depth++;
    } else if (char === ")") {
      if (depth === 0) {
        return { text: "", malformed: true };
      }
      depth--;
    } else if (depth === 0) {
      result += char;
    }
  }
  if (depth !== 0) {
    return { text: "", malformed: true };
  }
  return { text: result, malformed: false };
}

/**
 * Evaluates whether an email's sender domain is verified via DMARC.
 * Rules:
 * - Return false if senderDomain is null, if there is more than one From header, or if there is no Authentication-Results header.
 * - Use only the FIRST Authentication-Results header (message order). Its first token before the first ";" must equal "mx.google.com" (case-insensitive), otherwise false.
 * - Remove parenthetical comments (including nested ones) from the value BEFORE parsing. Split on ";" and read each segment's leading method=result (case-insensitive).
 * - Verified only if there is a dmarc segment with result "pass" AND its header.from property equals senderDomain (case-insensitive). Anything malformed returns false.
 */
export function isSenderVerified(
  headers: HeaderItem[],
  senderDomain: string | null
): boolean {
  if (!senderDomain || typeof senderDomain !== "string") {
    return false;
  }
  const cleanSenderDomain = senderDomain.trim().toLowerCase();
  if (cleanSenderDomain.length === 0) {
    return false;
  }

  if (!Array.isArray(headers)) {
    return false;
  }

  const fromHeaders = headers.filter(
    (h) => h && typeof h.name === "string" && h.name.toLowerCase() === "from"
  );
  if (fromHeaders.length > 1) {
    return false;
  }

  const authHeaders = headers.filter(
    (h) =>
      h &&
      typeof h.name === "string" &&
      h.name.toLowerCase() === "authentication-results"
  );
  if (authHeaders.length === 0) {
    return false;
  }

  // Use only the FIRST Authentication-Results header (message order)
  const rawHeader = authHeaders[0].value;
  if (typeof rawHeader !== "string") {
    return false;
  }

  // Remove parenthetical comments (including nested ones) from the value BEFORE parsing
  const { text: cleaned, malformed } = stripParentheticalComments(rawHeader);
  if (malformed) {
    return false;
  }

  if (!cleaned.includes(";")) {
    return false;
  }

  const parts = cleaned.split(";");
  // Its first token before the first ";" must equal "mx.google.com" (case-insensitive)
  const serverPart = parts[0].trim();
  const serverTokens = serverPart.split(/\s+/).filter(Boolean);
  if (serverTokens.length === 0 || serverTokens[0].toLowerCase() !== "mx.google.com") {
    return false;
  }

  let hasDmarcPass = false;

  // Split on ";" and read each segment's leading method=result (case-insensitive)
  for (let i = 1; i < parts.length; i++) {
    const segment = parts[i].trim();
    if (!segment) continue;

    const methodMatch = segment.match(
      /^([a-zA-Z0-9_.-]+)\s*=\s*([a-zA-Z0-9_.-]+)(?:\s+(.*)|$)/s
    );
    if (!methodMatch) {
      return false; // Malformed segment
    }

    const method = methodMatch[1].toLowerCase();
    const result = methodMatch[2].toLowerCase();
    const rest = methodMatch[3] ?? "";

    if (method === "dmarc") {
      if (result !== "pass") {
        return false;
      }
      const propMatch = rest.match(/(?:^|\s)header\.from\s*=\s*(?:"([^"]*)"|([^\s;]+))/i);
      if (!propMatch) {
        return false;
      }
      const fromValue = (propMatch[1] ?? propMatch[2]).trim().toLowerCase();
      const isExactMatch = fromValue === cleanSenderDomain;
      const isRelaxedParentMatch =
        cleanSenderDomain.endsWith("." + fromValue) &&
        fromValue.split(".").filter(Boolean).length >= 2 &&
        !MULTI_PART_PUBLIC_SUFFIXES.has(fromValue);

      if (!isExactMatch && !isRelaxedParentMatch) {
        return false;
      }
      hasDmarcPass = true;
    }
  }

  return hasDmarcPass;
}
