export interface OtpInput {
  subject?: string;
  body: string;
}

export interface OtpResult {
  code: string;
  raw: string;
  confidence: "high" | "medium";
}

interface ScoredCandidate {
  code: string;
  raw: string;
  confidence: "high" | "medium";
  index: number;
}

const KEYWORD_TOKENS = /\b(?:security\s+code|verification|passcode|verify|code|otp)\b/i;
const SUBJECT_KEYWORD_REGEX = /\b(?:security\s+code|verification|passcode|verify|code|otp)\b/i;
const PHONE_PATTERN_REGEX = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
const CANDIDATE_REGEX = /\b(G-[0-9]{4,8}|[0-9]{1,4}(?:-[0-9]{1,4})+|[0-9]{1,4}(?: [0-9]{1,4})+|[A-Z0-9]{6,8}|[0-9]{4,8})\b/g;

/**
 * Checks if the subject line contains an OTP-related keyword.
 */
export function hasSubjectKeyword(subject?: string): boolean {
  if (!subject) return false;
  return SUBJECT_KEYWORD_REGEX.test(subject);
}

/**
 * Checks if a 4-digit code represents a year in 1990-2100.
 */
export function isYear(code: string): boolean {
  if (/^\d{4}$/.test(code)) {
    const val = Number(code);
    return val >= 1990 && val <= 2100;
  }
  return false;
}

/**
 * Checks if candidate is prefixed with # (order numbers).
 */
export function isPrefixedWithHash(text: string, startIndex: number): boolean {
  const before = text.slice(Math.max(0, startIndex - 5), startIndex);
  return /#\s*$/.test(before);
}

/**
 * Checks if candidate is immediately adjacent to currency symbols or formatted as an amount.
 */
export function hasCurrency(text: string, startIndex: number, endIndex: number): boolean {
  const before = text.slice(Math.max(0, startIndex - 10), startIndex);
  const after = text.slice(endIndex, Math.min(text.length, endIndex + 10));

  if (/[$€£¥₹]\s*$/.test(before) || /^\s*[$€£¥₹]/.test(after)) return true;
  if (/\b(?:USD|EUR|GBP|CAD|AUD|INR)\s*$/i.test(before) || /^\s*(?:USD|EUR|GBP|CAD|AUD|INR)\b/i.test(after)) return true;
  if (/^\.\d{2}\b/.test(after)) return true;

  return false;
}

/**
 * Checks if the candidate is part of a telephone number pattern.
 */
export function isPhoneNumber(text: string, startIndex: number, endIndex: number, raw: string): boolean {
  const digitsOnly = raw.replace(/\D/g, "");
  if (digitsOnly.length >= 9) return true;

  for (const m of text.matchAll(PHONE_PATTERN_REGEX)) {
    const pStart = m.index;
    const pEnd = pStart + m[0].length;
    if (startIndex >= pStart && endIndex <= pEnd) return true;
  }

  return false;
}

/**
 * Checks if an alphanumeric candidate is 6-8 chars uppercase and contains both a letter and a digit.
 */
export function isValidAlphanumeric(raw: string): boolean {
  if (raw.length < 6 || raw.length > 8) return false;
  if (!/^[A-Z0-9]+$/.test(raw)) return false;
  return /[A-Z]/.test(raw) && /[0-9]/.test(raw);
}

/**
 * Checks if the candidate appears near an OTP keyword within its sentence context.
 */
export function isKeywordAdjacent(text: string, startIndex: number, endIndex: number): boolean {
  const windowStart = Math.max(0, startIndex - 80);
  const windowEnd = Math.min(text.length, endIndex + 80);

  const rawBefore = text.slice(windowStart, startIndex);
  const rawAfter = text.slice(endIndex, windowEnd);

  const beforeParts = rawBefore.split(/[.!?]\s+/);
  const before = beforeParts[beforeParts.length - 1] ?? rawBefore;

  let after = rawAfter;
  const nextSentenceEnd = rawAfter.search(/[.!?](?:\s|$)/);
  if (nextSentenceEnd !== -1) {
    after = rawAfter.slice(0, nextSentenceEnd);
  }

  if (KEYWORD_TOKENS.test(before) || KEYWORD_TOKENS.test(after)) return true;
  if (/\buse\b/i.test(before) && /^\s*to\b/i.test(rawAfter)) return true;
  if (/\benter\b/i.test(before)) return true;
  if (/\bis\b[:\s]*$/i.test(before.trimEnd())) return true;
  if (/^\s*is\b/i.test(rawAfter)) return true;

  return false;
}

/**
 * Scans a section (subject or body) for OTP candidates.
 */
function scanSection(
  text: string,
  offset: number,
  subjectHasKw: boolean,
  isSubject: boolean
): ScoredCandidate[] {
  const candidates: ScoredCandidate[] = [];

  for (const match of text.matchAll(CANDIDATE_REGEX)) {
    const raw = match[0];
    const startIndex = match.index;
    const endIndex = startIndex + raw.length;

    let code = raw;
    if (raw.startsWith("G-") || raw.startsWith("g-")) {
      code = raw.slice(2);
      if (!/^\d{4,8}$/.test(code)) continue;
    } else if (raw.includes("-") || raw.includes(" ")) {
      code = raw.replace(/[-\s]/g, "");
      if (!/^\d{4,8}$/.test(code)) continue;
    } else if (/[A-Z]/.test(raw)) {
      if (!isValidAlphanumeric(raw)) continue;
    } else if (/^\d{4,8}$/.test(raw)) {
      code = raw;
    } else {
      continue;
    }

    if (code.length >= 9 || raw.replace(/\D/g, "").length >= 9) continue;
    if (isYear(code)) continue;
    if (isPrefixedWithHash(text, startIndex)) continue;
    if (hasCurrency(text, startIndex, endIndex)) continue;
    if (isPhoneNumber(text, startIndex, endIndex, raw)) continue;

    const adjacent = isKeywordAdjacent(text, startIndex, endIndex);
    let confidence: "high" | "medium" | null = null;

    if (adjacent) {
      confidence = "high";
    } else if (!isSubject && subjectHasKw && /^\d{6}$/.test(raw)) {
      confidence = "medium";
    }

    if (!confidence) continue;

    candidates.push({
      code,
      raw,
      confidence,
      index: offset + startIndex
    });
  }

  return candidates;
}

/**
 * Extracts the best OTP candidate from an email input.
 */
export function extractOtp(input: { subject?: string; body: string }): OtpResult | null {
  const subjectRaw = input.subject?.trim() ?? "";
  const bodyRaw = input.body ?? "";

  const subjectScanned = subjectRaw.slice(0, 5000);
  const remainingBudget = 5000 - subjectScanned.length;
  const bodyScanned = remainingBudget > 0 ? bodyRaw.slice(0, remainingBudget) : "";

  const subjectHasKw = hasSubjectKeyword(subjectScanned);

  const candidates: ScoredCandidate[] = [
    ...scanSection(subjectScanned, 0, subjectHasKw, true),
    ...scanSection(
      bodyScanned,
      subjectScanned.length ? subjectScanned.length + 1 : 0,
      subjectHasKw,
      false
    )
  ];

  if (candidates.length === 0) return null;

  candidates.sort((a, b) => {
    if (a.confidence !== b.confidence) {
      return a.confidence === "high" ? -1 : 1;
    }
    return a.index - b.index;
  });

  return {
    code: candidates[0].code,
    raw: candidates[0].raw,
    confidence: candidates[0].confidence
  };
}
