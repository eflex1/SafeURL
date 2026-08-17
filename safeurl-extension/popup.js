document.addEventListener("DOMContentLoaded", function () {
  // Grab our UI elements
  const currentUrlEl = document.getElementById("currentUrl");
  const statusTextEl = document.getElementById("statusText");
  const riskScoreEl = document.getElementById("riskScore");
  const statusBoxEl = document.getElementById("statusBox");
  const scanBtn = document.getElementById("scanBtn");

  // Function to get the URL of the current active tab
  function getCurrentTabUrl() {
    statusTextEl.textContent = "Scanning...";
    riskScoreEl.textContent = "--%";
    statusBoxEl.style.borderTopColor = "#bdc3c7"; // reset to gray

    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      let url = tabs[0].url;

      // Ignore chrome:// internal pages
      if (url.startsWith("chrome://")) {
        currentUrlEl.textContent = "Internal Browser Page";
        updateUI(0, "SAFE");
        return;
      }

      currentUrlEl.textContent = url;
      analyzeUrl(url);
    });
  }

  async function analyzeUrl(url) {
    try {
      const response = await fetch('https://safeurl-backend-api.onrender.com/predict', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })
      });

      const data = await response.json();

      // Convert decimal probability to percentage
      const score = Math.round(data.probability * 100);
      updateUI(score, data.status);
    } catch (error) {
      console.error("Error connecting to SafeURL API:", error);
      statusTextEl.textContent = "API OFFLINE";
      riskScoreEl.textContent = "ERR";
    }
  }

  // Updates the HTML based on the risk score
  function updateUI(score, status) {
    riskScoreEl.textContent = score + "%";
    statusTextEl.textContent = status;

    if (status === "PHISHING") {
      statusBoxEl.style.borderTopColor = "#e74c3c"; // Red
      statusTextEl.style.color = "#e74c3c";
    } else if (status === "SUSPICIOUS") {
      statusBoxEl.style.borderTopColor = "#f1c40f"; // Yellow
      statusTextEl.style.color = "#f1c40f";
    } else {
      statusBoxEl.style.borderTopColor = "#2ecc71"; // Green
      statusTextEl.style.color = "#2ecc71";
    }
  }

  // Run the scan immediately when the popup is opened
  getCurrentTabUrl();

  // Allow the user to force a re-scan
  scanBtn.addEventListener("click", getCurrentTabUrl);
});
