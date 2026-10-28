# Privacy Policy

AutoOTP is built with a local-first, privacy-focused design. Your data remains on your computer under your control.

## What Data Is Read
- **Gmail Messages**: AutoOTP requests access solely using the read-only Gmail OAuth scope (`https://www.googleapis.com/auth/gmail.readonly`).
- **Local Message Processing**: Incoming messages are fetched and parsed entirely on your local machine to extract verification codes. To decide auto-fill, only the DMARC result from Gmail's `Authentication-Results` header is evaluated; SPF and DKIM values are present in the header but not independently checked by AutoOTP.
- **Ephemeral In-Memory Handling**: Full message bodies and email contents are processed in memory and immediately discarded. Raw email contents are never stored on disk or transmitted outside your computer.

## What Is Stored on Your Machine and for How Long
AutoOTP stores its application data in `~/.autootp` (or `$AUTOOTP_HOME`):
- `credentials.json`: Your downloaded Google Cloud OAuth client credentials (saved with restrictive permissions `0600`).
- `tokens.enc` & `key`: Google OAuth refresh tokens encrypted with AES-256-GCM. Stored until you remove the account (`autootp remove <alias>`) or delete the data directory.
- `history.db`: An encrypted local SQLite database storing recently detected OTPs. Records are automatically purged according to your configured `historyRetention` setting (`5m` by default; options: `off`, `5m`, `30m`, `1h`). You can immediately wipe all history using `autootp clear`.
- `status.json`: A transient status file containing the background service PID, port, active client count, and the sender domain/timestamp of the last detected OTP. It **never** contains OTP codes, tokens, or email bodies. This file is removed when the service shuts down cleanly.
- `logs/` (macOS only): Background service output is redirected to `~/.autootp/logs/service.log` when run via macOS launchd (with codes masked). On Linux, service output goes to the systemd user journal (view with `journalctl --user -u autootp.service`), not to a file in `~/.autootp/logs/`. In all non-terminal logs, detected OTP codes are replaced with `******`.
- `pair.token`: A per-installation pairing secret used by the browser extension to authenticate with the local WebSocket server.
- `config.json`: Local user configuration and paired extension IDs.

## What Is Sent Anywhere
- **Google APIs Only**: Network requests are sent exclusively to official Google endpoints (`oauth2.googleapis.com` for token exchange/refresh and `gmail.googleapis.com` for reading emails).
- **No Telemetry or Tracking**: AutoOTP contains **no analytics**, **no tracking**, **no telemetry**, and **no crash reporting**.
- **No External Servers**: There are no proxy servers, backend APIs, or remote services operated by the author or third parties. All communication between the background service and browser extension occurs strictly over the local loopback interface (`127.0.0.1`).

## How to Delete Everything
To completely remove all AutoOTP data, credentials, and installed components:

1. **Revoke and remove accounts**:
   ```bash
   autootp remove <alias>
   ```
   (Repeat for each connected account to revoke tokens with Google and delete local credentials).

2. **Clear OTP history**:
   ```bash
   autootp clear
   ```

3. **Disable and remove background service**:
   ```bash
   autootp disable
   ```
   (Removes `~/.config/systemd/user/autootp.service` on Linux).

4. **Delete data directory**:
   ```bash
   rm -rf ~/.autootp
   ```
   (Removes all local configuration, keys, encrypted tokens, database, and logs).

5. **Remove the browser extension**:
   Open `chrome://extensions`, locate **AutoOTP**, and click **Remove**.

6. **Uninstall the package**:
   ```bash
   npm uninstall -g autootp
   ```

## Why the Extension Needs Each Permission
The browser extension declares only two permissions in its `manifest.json`:
- `"storage"`: Used to store user preferences and the local WebSocket pairing token in `chrome.storage.local`.
- `"alarms"`: Used to schedule periodic heartbeat timers so the background service worker maintains an active connection to the local service.
- **Content Scripts on `https://*/*`**: Injected exclusively on secure HTTPS web pages to detect two-factor authentication / OTP input fields and fill verified codes. The extension never runs on plain unencrypted HTTP pages.
