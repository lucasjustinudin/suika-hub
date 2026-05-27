// Popup logic
const SERVER_URL = "http://localhost:9999";

// Update stats
function updateStats() {
  chrome.runtime.sendMessage({ action: "getStats" }, (resp) => {
    if (!resp) return;
    document.getElementById("cookies").textContent = resp.cookies;
    document.getElementById("headers").textContent = resp.headers;
    document.getElementById("requests").textContent = resp.requests;
    document.getElementById("endpoints").textContent = resp.endpoints;
    renderDomains(resp.domains || []);
  });
}

// Render domain tags
function renderDomains(domains) {
  const list = document.getElementById("domainList");
  list.innerHTML = domains.map(d => 
    `<span class="domain-tag" data-domain="${d}">${d} x</span>`
  ).join("");

  // Click to remove
  list.querySelectorAll(".domain-tag").forEach(tag => {
    tag.addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "removeDomain", domain: tag.dataset.domain }, updateStats);
    });
  });
}

// Add domain
document.getElementById("addDomain").addEventListener("click", () => {
  const input = document.getElementById("domain");
  const domain = input.value.trim();
  if (!domain) return;
  chrome.runtime.sendMessage({ action: "addDomain", domain }, () => {
    input.value = "";
    updateStats();
  });
});

// Enter key
document.getElementById("domain").addEventListener("keypress", (e) => {
  if (e.key === "Enter") document.getElementById("addDomain").click();
});

// Export session
document.getElementById("exportBtn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "getStats" }, (resp) => {
    if (resp.domains && resp.domains.length > 0) {
      chrome.runtime.sendMessage({ action: "exportSession", domain: resp.domains[0] }, (result) => {
        const status = document.getElementById("status");
        if (result && result.error) {
          status.textContent = result.error;
          status.className = "status";
        } else {
          status.textContent = "Session exported! Ready to scan.";
          status.className = "status connected";
        }
      });
    }
  });
});

// Clear
document.getElementById("clearBtn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "clear" }, updateStats);
});

// Check server status
async function checkServer() {
  const status = document.getElementById("status");
  try {
    const resp = await fetch(`${SERVER_URL}/health`);
    if (resp.ok) {
      status.textContent = "CLI server connected";
      status.className = "status connected";
    }
  } catch {
    status.textContent = "CLI server offline - run: python suika.py server";
    status.className = "status";
  }
}

// Init
updateStats();
checkServer();
setInterval(updateStats, 2000);
