import {
  MIN_BACKOFF_MS,
  getNextBackoff,
  parseIncomingMessage,
  ConnectionStatus
} from "./logic.js";

const WS_URL = "ws://127.0.0.1:47821";
const ALARM_NAME = "autootp_reconnect";

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let currentBackoffMs = MIN_BACKOFF_MS;
let tokenRejected = false;
let isConnecting = false;

async function getToken(): Promise<string | null> {
  try {
    const res = await chrome.storage.local.get(["token", "pairToken"]);
    const val = (res.token || res.pairToken) as unknown;
    if (typeof val === "string" && val.trim().length > 0) {
      return val.trim();
    }
  } catch {}
  return null;
}

async function updateStatus(status: ConnectionStatus): Promise<void> {
  try {
    await chrome.storage.session.set({ status });
  } catch {}
}

function clearReconnectTimer(): void {
  if (reconnectTimer !== null) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

function scheduleReconnect(): void {
  if (tokenRejected || reconnectTimer !== null) {
    return;
  }
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    currentBackoffMs = getNextBackoff(currentBackoffMs);
    connect();
  }, currentBackoffMs);
}

async function connect(): Promise<void> {
  clearReconnectTimer();

  if (tokenRejected) {
    await updateStatus("token_rejected");
    return;
  }

  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const token = await getToken();
  if (!token) {
    tokenRejected = false;
    await updateStatus("not_paired");
    return;
  }

  isConnecting = true;
  await updateStatus("connecting");

  try {
    const socket = new WebSocket(WS_URL);
    ws = socket;

    socket.onopen = () => {
      if (ws !== socket) return;
      socket.send(JSON.stringify({ type: "auth", token }));
    };

    socket.onmessage = async (event: MessageEvent) => {
      if (ws !== socket) return;
      const msg = parseIncomingMessage(event.data);
      if (!msg) {
        // Ignore unknown or malformed messages
        return;
      }

      if (msg.type === "hello") {
        isConnecting = false;
        tokenRejected = false;
        currentBackoffMs = MIN_BACKOFF_MS;
        await updateStatus("connected");
        return;
      }

      if (msg.type === "ping") {
        socket.send(JSON.stringify({ type: "pong" }));
        return;
      }

      if (msg.type === "otp") {
        const { sender, senderDomain, code, account, receivedAt } = msg;
        await chrome.storage.session.set({
          latestOtp: { sender, senderDomain, code, account, receivedAt },
          otp: { sender, senderDomain, code, account, receivedAt }
        });
      }
    };

    socket.onclose = async (event: CloseEvent) => {
      if (ws === socket) {
        ws = null;
      }
      isConnecting = false;

      // Close code 4401 means token rejected
      if (event.code === 4401) {
        tokenRejected = true;
        clearReconnectTimer();
        await updateStatus("token_rejected");
        return;
      }

      const activeToken = await getToken();
      if (!activeToken) {
        await updateStatus("not_paired");
        return;
      }

      await updateStatus("service_not_running");
      scheduleReconnect();
    };

    socket.onerror = () => {
      // socket.onclose will fire right after onerror
    };
  } catch {
    ws = null;
    isConnecting = false;
    await updateStatus("service_not_running");
    scheduleReconnect();
  }
}

// Ensure content scripts cannot read pairing token
async function configureAccessLevel(): Promise<void> {
  try {
    if (chrome.storage?.local?.setAccessLevel) {
      await chrome.storage.local.setAccessLevel({
        accessLevel: "TRUSTED_CONTEXTS"
      });
    }
  } catch {}
}

// On install, restrict storage access and configure recurring alarm
chrome.runtime.onInstalled.addListener(() => {
  configureAccessLevel();
  chrome.alarms.create(ALARM_NAME, { periodInMinutes: 1 });
  connect();
});

// Alarm triggers periodic health check / reconnection if disconnected
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) {
    if (!tokenRejected && (!ws || ws.readyState === WebSocket.CLOSED)) {
      connect();
    }
  }
});

// React to token updates or deletion in storage
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && ("token" in changes || "pairToken" in changes)) {
    const change = changes.token || changes.pairToken;
    const newToken = change?.newValue;

    tokenRejected = false;
    currentBackoffMs = MIN_BACKOFF_MS;
    clearReconnectTimer();

    if (ws) {
      ws.close();
      ws = null;
    }

    if (typeof newToken === "string" && newToken.trim().length > 0) {
      connect();
    } else {
      updateStatus("not_paired");
    }
  }
});

// Listen to commands from popup
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "connect" || message?.type === "reconnect") {
    tokenRejected = false;
    currentBackoffMs = MIN_BACKOFF_MS;
    clearReconnectTimer();
    connect();
    sendResponse?.({ ok: true });
    return true;
  }
  if (message?.type === "forget") {
    tokenRejected = false;
    currentBackoffMs = MIN_BACKOFF_MS;
    clearReconnectTimer();
    if (ws) {
      ws.close();
      ws = null;
    }
    updateStatus("not_paired");
    sendResponse?.({ ok: true });
    return true;
  }
  return false;
});

// Run initial connect when service worker starts
configureAccessLevel();
connect();
