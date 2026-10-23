export interface OtpInput {
  subject?: string;
  body: string;
}

export interface OtpResult {
  code: string;
  raw: string;
  confidence: "high" | "medium";
}

export interface KeywordTableEntry {
  language: string;
  phrases: string[];
}

export const KEYWORD_TABLE: KeywordTableEntry[] = [
  {
    language: "en",
    phrases: [
      "verification code",
      "security code",
      "passcode",
      "one-time password",
      "login code",
      "confirmation code",
      "authentication code",
      "auth code",
      "verification",
      "verify",
      "code",
      "otp"
    ]
  },
  {
    language: "es",
    phrases: [
      "código de verificación",
      "codigo de verificacion",
      "clave de verificación",
      "clave de verificacion",
      "código",
      "codigo"
    ]
  },
  {
    language: "fr",
    phrases: [
      "code de vérification",
      "code de verification",
      "code de confirmation",
      "code de sécurité",
      "code de securite",
      "code"
    ]
  },
  {
    language: "de",
    phrases: [
      "bestätigungscode",
      "verifizierungscode",
      "sicherheitscode",
      "code"
    ]
  },
  {
    language: "pt",
    phrases: [
      "código de verificação",
      "codigo de verificacao",
      "código de confirmação",
      "codigo de confirmacao",
      "código",
      "codigo"
    ]
  },
  {
    language: "it",
    phrases: [
      "codice di verifica",
      "codice di conferma",
      "codice di sicurezza",
      "codice"
    ]
  },
  {
    language: "ar",
    phrases: [
      "رمز التحقق",
      "كود التحقق",
      "رمز التأكيد",
      "كود التأكيد",
      "رمز",
      "كود"
    ]
  },
  {
    language: "am",
    phrases: [
      "የማረጋገጫ ኮድዎ",
      "የማረጋገጫ ኮድ",
      "የማረጋገጫ ቁጥር",
      "ኮድዎ",
      "ኮድ"
    ]
  }
];

// Helper to escape regex special characters and allow multiple whitespace between words
function buildPhraseRegexPattern(phrases: string[]): string {
  const sorted = [...phrases].sort((a, b) => b.length - a.length);
  return sorted
    .map(p => {
      const parts = p.trim().split(/\s+/);
      return parts.map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("\\s+");
    })
    .join("|");
}

const ALL_PHRASES = KEYWORD_TABLE.flatMap(e => e.phrases);
const KEYWORD_PATTERN = buildPhraseRegexPattern(ALL_PHRASES);

const KEYWORD_SCAN_REGEX = new RegExp(`(?<![\\p{L}\\p{N}])(?:${KEYWORD_PATTERN})(?![\\p{L}\\p{N}])`, "giu");
const KEYWORD_TEST_REGEX = new RegExp(`(?<![\\p{L}\\p{N}])(?:${KEYWORD_PATTERN})(?![\\p{L}\\p{N}])`, "iu");

const PENALTY_REGEX = /\b(?:account\s+number|ending\s+in|last\s+4|order|tracking|invoice|receipt|amount|total|balance|reference|card)\b/gi;

const CANDIDATE_REGEX = /\b(?:[Gg]-[0-9]{4,8}|[0-9]{1,6}(?:[- ][0-9]{1,6})+|[A-Za-z0-9]{1,8}(?:-[A-Za-z0-9]{1,8})+|[A-Za-z0-9]{4,10})\b/g;

// Hard rejection patterns
const DATE_REGEX = /\b(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:\d{4}|\d{2})|(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:\d{4}|\d{2}))\b/g;
const TIME_REGEX = /\b\d{1,2}:\d{2}(?::\d{2})?(?:\s*(?:am|pm|AM|PM))?\b/g;
const PHONE_REGEX = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
const CARD_4X4_REGEX = /\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b/g;
const POSTAL_REGEX = /\b(?:ZIP|Postal(?:\s+Code)?|Postcode|P\.?O\.?\s*Box)\s*:?\s*\d{4,6}(?:-\d{4})?\b/gi;
const US_STATE_ZIP_REGEX = /\b(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)\s+\d{5}(?:-\d{4})?\b/g;
const DESCRIPTIVE_HYPHEN_REGEX = /^\d+-(?:digit|step|factor|char|character|min|minute|sec|second|hour|day)s?$/i;

interface CandidateMatch {
  code: string;
  raw: string;
  startIndex: number;
  endIndex: number;
  isAlnum: boolean;
}

interface ScoredCandidate {
  code: string;
  raw: string;
  confidence: "high" | "medium";
  score: number;
  index: number;
}

/**
 * Checks if the subject line contains an OTP-related keyword.
 */
export function hasSubjectKeyword(subject?: string): boolean {
  if (!subject) return false;
  return KEYWORD_TEST_REGEX.test(subject);
}

/**
 * Checks if a 4-digit code represents a year in 1900-2100.
 */
export function isYear(code: string): boolean {
  if (/^\d{4}$/.test(code)) {
    const val = Number(code);
    return val >= 1900 && val <= 2100;
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
  if (/^\.\d{2}\b/.test(after) || /^\.\d{2}/.test(after)) return true;
  if (/\.\d+$/.test(before)) return true;

  return false;
}

/**
 * Checks if the candidate is part of a telephone number pattern.
 */
export function isPhoneNumber(text: string, startIndex: number, endIndex: number, raw: string): boolean {
  const digitsOnly = raw.replace(/\D/g, "");
  if (digitsOnly.length >= 9) return true;

  PHONE_REGEX.lastIndex = 0;
  for (const m of text.matchAll(PHONE_REGEX)) {
    const pStart = m.index;
    const pEnd = pStart + m[0].length;
    if (Math.max(startIndex, pStart) < Math.min(endIndex, pEnd)) return true;
  }

  return false;
}

/**
 * Checks if an alphanumeric candidate is 6-10 chars uppercase and contains both a letter and a digit.
 */
export function isValidAlphanumeric(raw: string): boolean {
  if (raw.length < 6 || raw.length > 10) return false;
  if (!/^[A-Za-z0-9]+$/.test(raw)) return false;
  return /[A-Za-z]/.test(raw) && /[0-9]/.test(raw);
}

/**
 * Checks if the candidate appears near an OTP keyword within its sentence context.
 */
export function isKeywordAdjacent(text: string, startIndex: number, endIndex: number): boolean {
  const windowStart = Math.max(0, startIndex - 80);
  const windowEnd = Math.min(text.length, endIndex + 80);

  const rawBefore = text.slice(windowStart, startIndex);
  const rawAfter = text.slice(endIndex, windowEnd);

  const beforeParts = rawBefore.split(/[.!?\n]\s*/);
  const before = beforeParts[beforeParts.length - 1] ?? rawBefore;

  let after = rawAfter;
  const nextSentenceEnd = rawAfter.search(/[.!?\n](?:\s|$)/);
  if (nextSentenceEnd !== -1) {
    after = rawAfter.slice(0, nextSentenceEnd);
  }

  if (KEYWORD_TEST_REGEX.test(before) || KEYWORD_TEST_REGEX.test(after)) return true;
  if (/\buse\b/i.test(before) && /^\s*to\b/i.test(rawAfter)) return true;
  if (/\benter\b/i.test(before)) return true;
  if (/\bis\b[:\s]*$/i.test(before.trimEnd())) return true;
  if (/^\s*is\b/i.test(rawAfter)) return true;

  return false;
}

function overlaps(start1: number, end1: number, start2: number, end2: number): boolean {
  return Math.max(start1, start2) < Math.min(end1, end2);
}

function normalizeCandidate(raw: string): { code: string; isAlnum: boolean } | null {
  if (DESCRIPTIVE_HYPHEN_REGEX.test(raw)) return null;
  if (raw.startsWith("G-") || raw.startsWith("g-")) {
    const code = raw.slice(2);
    if (!/^\d{4,8}$/.test(code)) return null;
    return { code, isAlnum: false };
  }
  if (raw.includes("-") || raw.includes(" ")) {
    const code = raw.replace(/[-\s]/g, "");
    if (/^\d{4,8}$/.test(code)) return { code, isAlnum: false };
    if (/^[A-Za-z0-9]{6,10}$/.test(code) && /[A-Za-z]/.test(code) && /\d/.test(code)) {
      return { code, isAlnum: true };
    }
    return null;
  }
  if (/^\d{4,8}$/.test(raw)) {
    return { code: raw, isAlnum: false };
  }
  if (/^[A-Za-z0-9]{6,10}$/.test(raw) && /[A-Za-z]/.test(raw) && /\d/.test(raw)) {
    return { code: raw, isAlnum: true };
  }
  return null;
}

function scanSection(
  text: string,
  offset: number,
  subjectHasKw: boolean,
  isSubject: boolean
): ScoredCandidate[] {
  const candidates: ScoredCandidate[] = [];
  if (!text) return candidates;

  // Reset regex lastIndex
  DATE_REGEX.lastIndex = 0;
  TIME_REGEX.lastIndex = 0;
  PHONE_REGEX.lastIndex = 0;
  CARD_4X4_REGEX.lastIndex = 0;
  POSTAL_REGEX.lastIndex = 0;
  US_STATE_ZIP_REGEX.lastIndex = 0;
  KEYWORD_SCAN_REGEX.lastIndex = 0;
  PENALTY_REGEX.lastIndex = 0;
  CANDIDATE_REGEX.lastIndex = 0;

  // Collect hard rejection spans
  const rejectedSpans: [number, number][] = [];
  for (const m of text.matchAll(DATE_REGEX)) {
    if (m.index !== undefined) rejectedSpans.push([m.index, m.index + m[0].length]);
  }
  for (const m of text.matchAll(TIME_REGEX)) {
    if (m.index !== undefined) rejectedSpans.push([m.index, m.index + m[0].length]);
  }
  for (const m of text.matchAll(PHONE_REGEX)) {
    if (m.index !== undefined) rejectedSpans.push([m.index, m.index + m[0].length]);
  }
  for (const m of text.matchAll(CARD_4X4_REGEX)) {
    if (m.index !== undefined) rejectedSpans.push([m.index, m.index + m[0].length]);
  }
  for (const m of text.matchAll(POSTAL_REGEX)) {
    if (m.index !== undefined) rejectedSpans.push([m.index, m.index + m[0].length]);
  }
  for (const m of text.matchAll(US_STATE_ZIP_REGEX)) {
    if (m.index !== undefined) rejectedSpans.push([m.index, m.index + m[0].length]);
  }

  // Find all keyword and penalty positions in text
  const keywordMatches: { start: number; end: number }[] = [];
  for (const m of text.matchAll(KEYWORD_SCAN_REGEX)) {
    if (m.index !== undefined) {
      keywordMatches.push({ start: m.index, end: m.index + m[0].length });
    }
  }

  const penaltyMatches: { start: number; end: number }[] = [];
  for (const m of text.matchAll(PENALTY_REGEX)) {
    if (m.index !== undefined) {
      penaltyMatches.push({ start: m.index, end: m.index + m[0].length });
    }
  }

  for (const match of text.matchAll(CANDIDATE_REGEX)) {
    const raw = match[0];
    const startIndex = match.index;
    if (startIndex === undefined) continue;
    const endIndex = startIndex + raw.length;

    const norm = normalizeCandidate(raw);
    if (!norm) continue;
    const { code, isAlnum } = norm;

    // Hard rejections:
    if (code.length > 10) continue;
    if (isYear(code)) continue;
    if (isPrefixedWithHash(text, startIndex)) continue;
    if (hasCurrency(text, startIndex, endIndex)) continue;
    if (rejectedSpans.some(([s, e]) => overlaps(startIndex, endIndex, s, e))) continue;

    // Check candidate alone on its own line
    const lineStart = text.lastIndexOf("\n", startIndex) + 1;
    const lineEndIdx = text.indexOf("\n", endIndex);
    const lineEnd = lineEndIdx === -1 ? text.length : lineEndIdx;
    const lineTrimmed = text.slice(lineStart, lineEnd).trim();
    const isAloneOnLine = lineTrimmed === raw;

    // Clause boundaries for penalty and keyword proximity
    const clauseStart = Math.max(0, text.lastIndexOf(".", startIndex) + 1, text.lastIndexOf("\n", startIndex) + 1);
    const nextPeriod = text.indexOf(".", endIndex);
    const nextNewline = text.indexOf("\n", endIndex);
    let clauseEnd = text.length;
    if (nextPeriod !== -1 && nextPeriod < clauseEnd) clauseEnd = nextPeriod;
    if (nextNewline !== -1 && nextNewline < clauseEnd) clauseEnd = nextNewline;

    // Proximity to keywords
    let minKwDist = Infinity;
    for (const kw of keywordMatches) {
      let dist: number;
      if (kw.end <= startIndex) dist = startIndex - kw.end;
      else if (kw.start >= endIndex) dist = kw.start - endIndex;
      else dist = 0;
      if (dist < minKwDist) minKwDist = dist;
    }

    // Check contextual phrasing: "Use 483921 to continue", "Enter code: 483921"
    const beforeClause = text.slice(clauseStart, startIndex);
    const afterClause = text.slice(endIndex, clauseEnd);
    let isContextual = false;
    if (/\buse\b/i.test(beforeClause) && /^\s*to\b/i.test(afterClause)) isContextual = true;
    if (/\benter\b/i.test(beforeClause)) isContextual = true;
    if (/\b(?:is|code[:\s]+)$/i.test(beforeClause.trimEnd())) isContextual = true;

    // Check penalty words:
    let minPenDist = Infinity;
    for (const p of penaltyMatches) {
      if (p.start >= clauseStart && p.end <= clauseEnd) {
        let dist: number;
        if (p.end <= startIndex) dist = startIndex - p.end;
        else if (p.start >= endIndex) dist = p.start - endIndex;
        else dist = 0;
        if (dist < minPenDist) minPenDist = dist;
      }
    }

    // SCORING:
    let score = 0;

    if (isContextual) {
      score += 70;
    } else if (minKwDist <= 30) {
      score += 70;
    } else if (minKwDist <= 60) {
      score += 45;
    } else if (minKwDist <= 100) {
      score += 30;
    } else if (minKwDist <= 150) {
      score += 15;
    }

    if (subjectHasKw) {
      score += 25;
    }

    if (isAloneOnLine) {
      score += 20;
    }

    if (code.length === 6) {
      score += 15;
    }

    if (isAlnum && /^[A-Z0-9]+$/.test(code)) {
      score += 15;
    }

    // Penalty application:
    if (minPenDist <= 25) {
      score -= 60;
    } else if (minPenDist <= 50) {
      score -= 40;
    }

    if (score < 40) continue;

    const confidence: "high" | "medium" = score >= 70 ? "high" : "medium";

    candidates.push({
      code,
      raw,
      confidence,
      score,
      index: offset + startIndex
    });
  }

  return candidates;
}

/**
 * Extracts the best OTP candidate from an email input.
 */
export function extractOtp(input: OtpInput): OtpResult | null {
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
    if (b.score !== a.score) {
      return b.score - a.score;
    }
    return a.index - b.index;
  });

  return {
    code: candidates[0].code,
    raw: candidates[0].raw,
    confidence: candidates[0].confidence
  };
}
