# AutoOTP

Automated one-time password (OTP) detection and autofill for Gmail.

## What it does

AutoOTP monitors your Gmail inbox in real time for incoming two-factor authentication (2FA) codes and one-time passwords. When a code arrives, AutoOTP verifies the sender domain against the active website tab in your Chromium-based browser and automatically fills the code into the verification input form on matching verified domains, or provides a one-click manual fill button when sender verification requires confirmation.

## How it works

```text
Gmail API -> background service -> local WebSocket -> browser extension -> page
```

- **Gmail API**: Connects securely to Gmail via read-only Google OAuth (`gmail.readonly`) to inspect incoming verification messages.
- **Background service**: Runs locally, scores candidate OTPs, inspects SPF/DKIM/DMARC authentication results, logs masked diagnostic events, and persists encrypted history according to retention settings.
- **Local WebSocket**: Dispatches real-time OTP events over `127.0.0.1:47821` protected by an extension pairing secret, origin checks, and connection limits.
- **Browser extension**: Background worker receives the event, inspects the active browser tab, and compares the sender domain to the page hostname.
- **Page**: If the sender domain matches the page hostname and DMARC passes, a content script fills the input field on secure HTTPS pages; otherwise, manual fill remains available via the popup.

## Requirements

- **Node.js**: Version >= 22.13
- **Browser**: A Chromium-based browser (Google Chrome, Brave, Microsoft Edge, Chromium)
- **Google Account**: A Google account with access to Google Cloud Console to create Desktop OAuth credentials
- **Linux**: Fully supported and verified with systemd user services
- **macOS**: Experimental (background service can be run manually or via launchd; built-in auto-start `enable` command is Linux-only)
- **Windows**: Foreground execution supported; no Windows auto-start service is available

## Install

Install globally via npm:

```bash
npm install -g autootp
```

Or run directly without global installation using `npx autootp`.

## Quick start

### Automated Setup

Run the interactive setup wizard:

```bash
autootp setup
```

The wizard guides you step-by-step:
1. Verifies that your Node.js runtime meets requirements (>= 22.13).
2. Provides Google Cloud setup instructions, validates your downloaded OAuth credentials JSON, and saves it to `~/.autootp/credentials.json` with permissions `0600`.
3. Connects your Gmail account (`personal` by default) via browser OAuth consent.
4. Locates the extension directory, pairs with the browser extension ID, and displays your pairing token.
5. Configures systemd auto-start at login (on Linux).
6. Runs `autootp doctor` diagnostic checks to verify end-to-end health.

### Manual Setup

1. **Google Cloud Credentials**:
   - Create a project in [Google Cloud Console](https://console.cloud.google.com/).
   - Enable the **Gmail API**.
   - Configure the OAuth consent screen (User type: **External**, add your email under **Test users**, add scope `https://www.googleapis.com/auth/gmail.readonly`).
   - Create OAuth Client ID with application type **Desktop app**.
   - Download the client secret JSON file and save it to `~/.autootp/credentials.json` with permissions `0600`:
     ```bash
     mkdir -p ~/.autootp
     cp ~/Downloads/client_secret_*.json ~/.autootp/credentials.json
     chmod 0600 ~/.autootp/credentials.json
     ```

2. **Connect Account**:
   ```bash
   autootp login personal
   ```

3. **Install Extension**:
   - Run `autootp extension-path` to print the extension directory path.
   - Open your Chromium browser to `chrome://extensions`.
   - Enable **Developer mode** (toggle in the top-right corner).
   - Click **Load unpacked** and select the extension directory.

4. **Pair Extension**:
   - Run `autootp extension-id` to view the extension ID.
   - Pair the extension:
     ```bash
     autootp pair <extensionId>
     ```
   - Open the AutoOTP extension popup in your browser, paste the printed pairing token, and click **Connect**.

5. **Start Service**:
   - On Linux with systemd, enable auto-start at login:
     ```bash
     autootp enable
     ```
   - On other platforms or for foreground debugging, run:
     ```bash
     autootp service
     ```

6. **Verify Health**:
   ```bash
   autootp doctor
   ```

## Commands

| Command | Arguments / Options | Description |
| :--- | :--- | :--- |
| `setup` | `[--dry-run]` | Interactive setup wizard for AutoOTP (`--dry-run` checks status without modifying anything) |
| `login` | `[alias]` | Connect a Gmail account via Google OAuth (default alias: `personal`) |
| `accounts` | None | List all connected Gmail accounts |
| `remove` | `<alias>` | Remove a connected account and revoke its tokens |
| `watch` | None | Watch connected Gmail accounts for incoming OTPs in the foreground |
| `pair` | `<extensionId>` | Pair a Chrome extension with AutoOTP and generate an authentication token |
| `service` | `[--no-watch]` | Start the AutoOTP background service and WebSocket server (`--no-watch` runs WebSocket only) |
| `enable` | None | Configure and enable AutoOTP to start automatically at login (Linux systemd) |
| `disable` | None | Disable and remove AutoOTP auto-start service |
| `status` | None | Display the current service status and connection info |
| `config` | None | Display current configuration settings |
| `config set` | `<key> <value>` | Set a configuration option (`historyRetention` or `notifications`) |
| `history` | None | Display recently received OTPs |
| `clear` | None | Clear all stored OTP history |
| `doctor` | None | Check AutoOTP system health and prerequisites |
| `audit` | `[--days N] [--account alias] [--subjects] [--explain]` | Read-only calibration tool for analyzing OTP detection on real inbox messages |
| `extension-path` | None | Print the absolute path to the browser extension directory |
| `extension-id` | None | Print the computed browser extension ID |

## Settings

View all settings by running:

```bash
autootp config
```

Modify settings using `autootp config set <key> <value>`:

- `historyRetention`:
  - **Description**: How long received OTPs are retained in the local encrypted SQLite database before secure deletion.
  - **Values**: `off`, `5m`, `30m`, `1h` (default: `5m`). Set to `off` to prevent saving any OTP records to disk.
  - **Example**: `autootp config set historyRetention 30m`

- `notifications`:
  - **Description**: Desktop notification behavior when an OTP is detected.
  - **Values**: `off`, `hidden`, `code` (default: `code`). `code` includes the OTP digits in the notification, `hidden` notifies without displaying the code, and `off` suppresses desktop notifications.
  - **Example**: `autootp config set notifications hidden`

## Security model

AutoOTP incorporates defense-in-depth protections designed for personal local use:

- **Local-only WebSocket on 127.0.0.1**: The server listens exclusively on loopback address `127.0.0.1` (port 47821). It requires an extension pairing token generated per-installation, verifies both `Origin` (`chrome-extension://<id>`) and `Host` (`127.0.0.1:<port>` or `localhost:<port>`), and strictly caps concurrent connections to a maximum of 5.
- **Read-only Gmail scope**: OAuth access is restricted exclusively to `https://www.googleapis.com/auth/gmail.readonly`. The application cannot send, modify, trash, or delete emails.
- **Encrypted OAuth refresh tokens**: Google OAuth refresh tokens are encrypted at rest with AES-256-GCM using a 256-bit key stored in `~/.autootp/key` alongside `~/.autootp/tokens.enc` (both with mode `0600`). *Note: This protects against casual filesystem inspection and unencrypted disk backups; it does not protect against malware executing as the same local operating system user.*
- **Log sanitization**: Detected OTP codes are replaced with `******` in non-terminal logs and log files. The status file (`status.json`) never contains codes, tokens, or email bodies.
- **Encrypted history and secure deletion**: OTP history is stored in an AES-encrypted SQLite database (`history.db`), automatically pruned according to the configured retention window, and immediately purged upon running `autootp clear`.
- **Autofill restrictions & DMARC verification**: Automated autofill runs exclusively on secure HTTPS pages (`https://`). Automatic autofill is triggered **only** when the email sender domain matches the active browser tab hostname and Gmail's `Authentication-Results` header reports `dmarc=pass`. If authentication checks fail or the domains differ, automated autofill is withheld and requires a manual **Fill** click in the extension popup.
- **Minimal extension permissions**: The browser extension requests only the `storage` and `alarms` permissions, along with a content script matching `https://*/*`.
- **Pair token isolation**: The pairing token is stored in `chrome.storage.local` and accessed exclusively by the extension background service worker. The token is never exposed to or accessible by page content scripts.

## Privacy

AutoOTP operates entirely on your local machine:
- Only incoming Gmail messages are read, and only using the read-only scope.
- Emails are processed in-memory locally to extract verification codes and verify sender authentication; full email bodies are never stored or transmitted.
- Network requests are sent solely to official Google APIs (`oauth2.googleapis.com` and `gmail.googleapis.com`).
- There are no third-party servers, no analytics, no telemetry, and no tracking.

For full details and complete data removal instructions, see [PRIVACY.md](PRIVACY.md).

## Troubleshooting

- **Diagnose system state**: Run `autootp doctor` to check Node.js version, configuration integrity, file permissions (`0600`), token validity, extension pairing, systemd service status, port availability, and desktop notification helpers (`notify-send` or `osascript`).
- **7-day Google login expiry while Google app is in Testing mode**: While your Google Cloud OAuth app is in "Testing" publishing status, Google automatically expires OAuth refresh tokens after 7 days. When expired, `autootp doctor` will indicate that the account needs re-authentication. Run `autootp login <alias>` to renew consent.
- **Notifications not appearing**: Ensure `notify-send` (`libnotify`) is installed on Linux or notification permissions are granted on macOS. Verify that `autootp config` shows `notifications` set to `code` or `hidden` (not `off`).
- **Extension not connecting**: Ensure the background service is running (`autootp status` or `systemctl --user status autootp.service`), verify port 47821 is listening, verify that the extension ID matches `autootp extension-id`, and verify that the pairing token (`~/.autootp/pair_token`) was pasted into the extension popup.

## Limitations

- **Native desktop apps are not filled**: AutoOTP autofills web forms inside Chromium-based browsers; native desktop applications (e.g., desktop clients) cannot be filled automatically. Use the extension popup's **Copy** button or desktop notifications to copy or view the code.
- **Sender check relies on Gmail's verdict**: Sender authentication depends on the `Authentication-Results` header provided by Gmail's incoming mail servers.
- **Senders with different site and email domains need a manual click**: When the sender email domain differs from the web application domain (e.g., authentication emails sent via third-party providers), automated autofill is suppressed for security and requires clicking **Fill** in the popup.
- **Bring-your-own Google credentials setup**: Requires creating a personal Google Cloud project and downloading OAuth desktop credentials.

## Not yet supported

- **Firefox and other non-Chromium browsers**
- **Outlook, Microsoft 365, and other email providers**
- **Windows auto-start** (running as a Windows background service is not yet supported; run `autootp service` in the foreground instead)
- **Clipboard copy** (automatic clipboard copying is omitted for security; use the popup Copy button)
- **Chrome Web Store availability** (the extension is currently installed unpacked via Developer mode)
- **Google app verification** (the personal OAuth application runs in Testing mode)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full license text.

Copyright (c) 2026 Abera Hagazi.

Security policy: [SECURITY.md](SECURITY.md)  
Privacy policy: [PRIVACY.md](PRIVACY.md)
