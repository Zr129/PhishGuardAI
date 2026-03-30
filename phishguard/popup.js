// Determine severity level based on deterministic keywords
function getLevel(reason) {
    const r = reason.toLowerCase();

    // High Severity: Direct theft mechanisms
    if (r.includes("password") || r.includes("blacklist") || r.includes("mismatch") || r.includes("ip-address")) {
        return "high";
    }

    // Medium Severity: Structural anomalies (Kits)
    if (r.includes("external") || r.includes("ratio") || r.includes("dead") || r.includes("empty")) {
        return "medium";
    }

    return "low";
}

function loadAnalysis() {
    // Note: Ensure this key 'analysisResult' matches what you set in background.js/content.js
    chrome.storage.local.get("analysisResult", (result) => {
        const wrapper = result.analysisResult;
        const statusDiv = document.getElementById("status");
        const confidenceDiv = document.getElementById("confidence");
        const reasonsDiv = document.getElementById("reasons");

        if (!wrapper || !wrapper.data) {
            statusDiv.innerText = "NO DATA";
            statusDiv.style.backgroundColor = "#95a5a6";
            reasonsDiv.innerHTML = "<div class='reason'>Visit a website to start analysis.</div>";
            return;
        }

        const data = wrapper.data;

        // 🔥 SET STATUS & COLOR
        statusDiv.innerText = data.prediction.toUpperCase();
        
        // Match colors to your Deterministic Actions
        if (data.action === "BLOCK") {
            statusDiv.style.backgroundColor = "#e74c3c"; // Red
        } else if (data.action === "WARN") {
            statusDiv.style.backgroundColor = "#f39c12"; // Orange
        } else {
            statusDiv.style.backgroundColor = "#2ecc71"; // Green
        }

        // 🔥 CONFIDENCE (Calculated from Score or Hardcoded in Deterministic)
        confidenceDiv.innerText = `Threat Certainty: ${Math.round(data.confidence * 100)}%`;

        // 🔥 REASONS LIST
        reasonsDiv.innerHTML = "";
        data.reasons.forEach(reason => {
            const div = document.createElement("div");
            const level = getLevel(reason);
            div.className = `reason ${level}`;
            div.innerText = reason;
            reasonsDiv.appendChild(div);
        });
    });
}

loadAnalysis();