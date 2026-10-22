/**
 * Error thrown when a configuration requirement (e.g. paired extension or connected account) is not met.
 * Corresponds to standard sysexits EX_CONFIG (78).
 */
export class ConfigurationError extends Error {
  readonly exitCode = 78;
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}
