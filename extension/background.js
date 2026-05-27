/**
 * Suika Hunter v2 - Background Service Worker
 * Auto-captures cookies, headers, and API requests
 * Sends to local CLI server at localhost:9999
 */

const SERVER_URL = "http://localhost:9999";
const CAPTURE_DOMAINS = new Set(); // Domains to capture (set via popup)
let capturedData = {
  cookies: {},
  headers: {},
  requests: [],
  endpoints: new Set(),
};

// Listen for web requests
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const url = new URL(details.url);
    
    if (!shouldCapture(url.hostname)) return;

    // Capture headers
    const headers = {};
    for (const header of details.requestHeaders || []) {
      headers[header.name] = header.value;
      
      // Save auth headers
      const name = header.name.toLowerCase();
      if (["authorization", "x-token", "x-api-key", "x-csrf-token", "cookie"].includes(name)) {
        capturedData.headers[header.name] = header.value;
      }
    }

    // Capture endpoint
    const endpoint = {
      method: details.method,
      url: details.url,
      path: url.pathname,
      params: Object.fromEntries(url.searchParams),
      headers: headers,
      timestamp: Date.now(),
    };

    capturedData.requests.push(endpoint);
    capturedData.endpoints.add(`${details.method} ${url.pathname}`);

    // Keep last 500 requests
    if (capturedData.requests.length > 500) {
      capturedData.requests = capturedData.requests.slice(-500);
    }

    // Auto-send to server
    sendToServer("request", endpoint);
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// Capture cookies on change
chrome.cookies.onChanged.addListener((changeInfo) => {
  const cookie = changeInfo.cookie;
  
  if (!shouldCapture(cookie.domain.replace(/^\./, ""))) return;

  if (!changeInfo.removed) {
    capturedData.cookies[cookie.name] = cookie.value;
    sendToServer("cookie", { name: cookie.name, value: cookie.value, domain: cookie.domain });
  }
});

// Check if domain should be captured
function shouldCapture(hostname) {
  if (CAPTURE_DOMAINS.size === 0) return false;
  for (const domain of CAPTURE_DOMAINS) {
    if (hostname.includes(domain)) return true;
  }
  return false;
}

// Send data to local server
async function sendToServer(type, data) {
  try {
    await fetch(`${SERVER_URL}/capture`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, data, timestamp: Date.now() }),
    });
  } catch (e) {
    // Server not running - silently fail
  }
}

// Export all captured data
async function exportSession(domain) {
  // Get all cookies for domain
  const cookies = await chrome.cookies.getAll({ domain });
  const cookieMap = {};
  for (const c of cookies) {
    cookieMap[c.name] = c.value;
  }

  const session = {
    domain,
    cookies: cookieMap,
    headers: capturedData.headers,
    endpoints: [...capturedData.endpoints],
    requests: capturedData.requests.filter(r => r.url.includes(domain)),
    exported_at: new Date().toISOString(),
  };

  // Send full session to server
  try {
    const resp = await fetch(`${SERVER_URL}/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(session),
    });
    return await resp.json();
  } catch (e) {
    return { error: "Server not running. Start: python suika.py server" };
  }
}

// Message handler from popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "addDomain") {
    CAPTURE_DOMAINS.add(msg.domain);
    chrome.storage.local.set({ domains: [...CAPTURE_DOMAINS] });
    sendResponse({ ok: true, domains: [...CAPTURE_DOMAINS] });
  }
  else if (msg.action === "removeDomain") {
    CAPTURE_DOMAINS.delete(msg.domain);
    chrome.storage.local.set({ domains: [...CAPTURE_DOMAINS] });
    sendResponse({ ok: true, domains: [...CAPTURE_DOMAINS] });
  }
  else if (msg.action === "getDomains") {
    sendResponse({ domains: [...CAPTURE_DOMAINS] });
  }
  else if (msg.action === "getStats") {
    sendResponse({
      cookies: Object.keys(capturedData.cookies).length,
      headers: Object.keys(capturedData.headers).length,
      requests: capturedData.requests.length,
      endpoints: capturedData.endpoints.size,
      domains: [...CAPTURE_DOMAINS],
    });
  }
  else if (msg.action === "exportSession") {
    exportSession(msg.domain).then(sendResponse);
    return true; // async response
  }
  else if (msg.action === "clear") {
    capturedData = { cookies: {}, headers: {}, requests: [], endpoints: new Set() };
    sendResponse({ ok: true });
  }
  return true;
});

// Restore domains from storage on startup
chrome.storage.local.get("domains", (result) => {
  if (result.domains) {
    for (const d of result.domains) CAPTURE_DOMAINS.add(d);
  }
});
