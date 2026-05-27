/**
 * Content script - detect current page context
 * Minimal footprint, only sends page metadata
 */

// Notify background about current page
chrome.runtime.sendMessage({
  action: "pageVisit",
  data: {
    url: window.location.href,
    domain: window.location.hostname,
    title: document.title,
  }
});
