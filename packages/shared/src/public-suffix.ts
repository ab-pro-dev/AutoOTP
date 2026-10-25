/**
 * Built-in approximation of the Public Suffix List (PSL).
 * Shared across packages to detect multi-part public suffixes and avoid improper domain grouping.
 */
export const MULTI_PART_PUBLIC_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "com.au",
  "net.au",
  "co.jp",
  "co.in",
  "co.za",
  "com.br",
  "com.et",
  "gov.et",
  "edu.et",
  "github.io",
  "vercel.app",
  "netlify.app",
  "pages.dev",
  "herokuapp.com",
  "blogspot.com",
  "web.app",
  "firebaseapp.com"
]);
