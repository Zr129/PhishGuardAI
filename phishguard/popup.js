// Determine severity level
function getLevel(reason) {
    const r = reason.toLowerCase();

    if (r.includes("blacklist") || r.includes("impersonation") || r.includes("password")) {
        return "high";
    }

    if (r.includes("external") || r.includes("forms") || r.includes("anchors")) {
        return "medium";
    }

    return "low";
}

// Load stored analysis
function loadAnalysis() {

    chrome.storage.local.get("analysisResult", (result) => {

        const wrapper = result.analysisResult;

        const statusDiv = document.getElementById("status");
        const confidenceDiv = document.getElementById("confidence");
        const reasonsDiv = document.getElementById("reasons");
        const noDataDiv = document.getElementById("noData");

        if (!wrapper || !wrapper.data) {
            statusDiv.innerText = "No Data";
            noDataDiv.style.display = "block";
            return;
        }

        const data = wrapper.data;

        // 🔥 STATUS TEXT
        statusDiv.innerText = data.prediction.toUpperCase();

        // 🔥 STATUS COLOR
        if (data.prediction === "phishing") {
            statusDiv.style.backgroundColor = "#e74c3c";
        } else if (data.prediction === "suspicious") {
            statusDiv.style.backgroundColor = "#f39c12";
        } else {
            statusDiv.style.backgroundColor = "#2ecc71";
        }

        // 🔥 CONFIDENCE
        confidenceDiv.innerText = `Confidence: ${Math.round(data.confidence * 100)}%`;

        // 🔥 REASONS LIST
        reasonsDiv.innerHTML = "";

        data.reasons.forEach(reason => {

            const div = document.createElement("div");

            const level = getLevel(reason);

            div.className = "reason " + level;

            div.innerText = reason;

            reasonsDiv.appendChild(div);
        });

    });
}

// Run when popup opens
loadAnalysis();