export class ReauthRequiredError extends Error {
  constructor(message: string = "Reauthorization required: refresh token is invalid or expired") {
    super(message);
    this.name = "ReauthRequiredError";
    Object.setPrototypeOf(this, ReauthRequiredError.prototype);
  }
}
