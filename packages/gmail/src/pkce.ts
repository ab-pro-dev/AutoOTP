import crypto from "node:crypto";

/**
 * Generates a 32-byte cryptographically random code verifier, base64url encoded.
 */
export function createVerifier(): string {
  return crypto.randomBytes(32).toString("base64url");
}

/**
 * Computes the code challenge from the verifier using SHA-256 and base64url encoding without padding.
 */
export function createChallenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

/**
 * Generates a cryptographically random state parameter, base64url encoded.
 */
export function createState(): string {
  return crypto.randomBytes(32).toString("base64url");
}
