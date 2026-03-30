// --- 1. SEVERITY ENGINE ---
function getLevel(reason) {
    const r = reason.toLowerCase();
    
    // High Severity: Direct theft or verified blacklists
    if (r.includes("password") || r.includes("blacklist") || 
        r.includes("mismatch") || r.includes("ip-address") || 
        r.includes("harvesting")) {
        return "high";
    }

    // Medium Severity: Structural patterns (Phish Kits)
    if (r.includes("external") || r.includes("ratio") || 
        r.includes("dead") || r.includes("empty") || 
        r.includes("anomaly")) {
        return "medium";
    }

    return "low";
}

// --- 2. THE RENDERER ---
function renderAnalysis() {
    chrome.storage.local.get("analysisResult", (result) => {
        const wrapper = result.analysisResult;
        
        const statusDiv = document.getElementById("status");
        const confidenceDiv = document.getElementById("confidence");
        const reasonsDiv = document.getElementById("reasons");
        const domainSpan = document.getElementById("current-domain");

        // Handle the "No Data" state
        if (!wrapper || !wrapper.data) {
            statusDiv.innerText = "IDLE";
            statusDiv.className = "status-pill idle";
            reasonsDiv.innerHTML = "<div class='reason low'>Visit a website to start analysis.</div>";
            return;
        }

        const { data, url } = wrapper;

        // 1. Update Domain Context
        try {
            const domainName = new URL(url).hostname.replace('www.', '');
            domainSpan.innerText = `Site: ${domainName}`;
        } catch (e) {
            domainSpan.innerText = "Unknown Site";
        }

        // 2. Update Status Pill (BLOCK, WARN, ALLOW)
        statusDiv.innerText = data.prediction.toUpperCase();
        statusDiv.className = `status-pill ${data.action.toLowerCase()}`;

        // 3. Update Confidence Meter
        const certainty = Math.round(data.confidence * 100);
        confidenceDiv.innerHTML = `Threat Certainty: <strong>${certainty}%</strong>`;
        
        const fill = document.getElementById("confidence-fill");
        fill.style.width = certainty + "%";
        fill.style.backgroundColor = data.action === "BLOCK" ? "#e74c3c" : (data.action === "WARN" ? "#f39c12" : "#27ae60");

        // 4. Render Reasons List
        reasonsDiv.innerHTML = "";
        
        if (data.reasons && data.reasons.length > 0) {
            data.reasons.forEach(reason => {
                const div = document.createElement("div");
                const level = getLevel(reason);
                
                div.className = `reason ${level}`;
                div.innerText = reason;
                reasonsDiv.appendChild(div);
            });
        } else {
            // "Safe" state
            reasonsDiv.innerHTML = `
                <div style="text-align:center; padding: 20px; color: #27ae60;">
                    <div style="font-size: 30px; margin-bottom: 5px;">✓</div>
                    <div style="font-size: 13px;">No immediate threats detected.</div>
                </div>`;
        }
    });
}

// --- 3. AUTO-UPDATE ---
// Refresh the popup if the background analysis finishes while popup is open
chrome.storage.onChanged.addListener((changes) => {
    if (changes.analysisResult) {
        renderAnalysis();
    }
});

// Initial load
document.addEventListener('DOMContentLoaded', renderAnalysis);