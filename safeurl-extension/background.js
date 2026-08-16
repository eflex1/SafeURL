// SafeURL Background Service Worker (Manifest V3)

chrome.webNavigation.onBeforeNavigate.addListener(function (details) {
  // We only want to monitor the main frame (the actual URL in the address bar), not hidden iframes
  if (details.frameId === 0) {
    let targetUrl = details.url;

    // Ignore internal Chrome pages
    if (targetUrl.startsWith("chrome://") || targetUrl.startsWith("edge://")) {
      return;
    }

    console.log("SafeURL Intercepted: ", targetUrl);

    /* 
      PHASE 2/3 INTEGRATION:
      Here we will send a POST request to our Node.js server.
      If the server responds with a risk >= 70%, we will trigger:
      chrome.tabs.update(details.tabId, { url: "warning.html" });
    */
  }
});
