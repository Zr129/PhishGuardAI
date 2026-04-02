// ===========================
// THEME SYSTEM
// ===========================

function applyTheme(theme) {
    const toggleBtn = document.getElementById("theme-toggle");

    if (theme === "dark") {
        document.body.classList.add("dark");
        if (toggleBtn) toggleBtn.innerText = "☀️";
    } else {
        document.body.classList.remove("dark");
        if (toggleBtn) toggleBtn.innerText = "🌙";
    }
}

function loadTheme() {
    chrome.storage.local.get("theme", (res) => {
        if (res.theme) {
            applyTheme(res.theme);
        } else {
            const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
            applyTheme(prefersDark ? "dark" : "light");
        }
    });
}

function setupThemeToggle() {
    const toggleBtn = document.getElementById("theme-toggle");
    if (!toggleBtn) return;

    toggleBtn.onclick = () => {
        const isDark = document.body.classList.contains("dark");
        const newTheme = isDark ? "light" : "dark";

        chrome.storage.local.set({ theme: newTheme });
        applyTheme(newTheme);
    };
}

// ===========================
// SEVERITY CLASSIFIER
// ===========================

function getLevel(reason) {
    const r = reason.toLowerCase();

    if (
        r.includes("password") ||
        r.includes("blacklist") ||
        r.includes("impersonation") ||
        r.includes("harvesting") ||
        r.includes("credential")
    ) return "high";

    if (
        r.includes("external") ||
        r.includes("ratio") ||
        r.includes("subdomain") ||
        r.includes("cloaked")
    ) return "medium";

    return "low";
}

// ===========================
// MAIN RENDER FUNCTION
// ===========================

function renderAnalysis() {
    chrome.storage.local.get("analysisResult", (result) => {

        const wrapper = result.analysisResult;

        const statusDiv = document.getElementById("status");
        const confidenceDiv = document.getElementById("confidence");
        const reasonsDiv = document.getElementById("reasons");
        const domainSpan = document.getElementById("current-domain");
        const fill = document.getElementById("confidence-fill");

        // ---------------------------
        // NO DATA STATE
        // ---------------------------
        if (!wrapper || !wrapper.data) {
            if (statusDiv) {
                statusDiv.innerText = "ANALYSING...";
                statusDiv.className = "status-pill idle";
            }

            if (confidenceDiv) {
                confidenceDiv.innerText = "Scanning website...";
            }

            if (fill) {
                fill.style.width = "10%";
                fill.style.background = "#95a5a6";
            }

            if (reasonsDiv) {
                reasonsDiv.innerHTML = `
                    <div class="safe-box">
                        🔍 Running analysis...
                    </div>
                `;
            }

            return;
        }

        const { data, url } = wrapper;

        // ---------------------------
        // OFFLINE / ERROR
        // ---------------------------
        if (data.prediction === "offline" || data.prediction === "error") {

            if (statusDiv) {
                statusDiv.innerText = "OFFLINE";
                statusDiv.className = "status-pill idle";
            }

            if (confidenceDiv) {
                confidenceDiv.innerText = "Backend unavailable";
            }

            if (fill) {
                fill.style.width = "0%";
            }

            if (reasonsDiv) {
                reasonsDiv.innerHTML = `
                    <div class="safe-box">
                        ⚠️ Backend not connected
                    </div>
                `;
            }

            return;
        }

        // ---------------------------
        // NORMAL FLOW
        // ---------------------------

        let c = data.confidence;
        if (c <= 1) c = c * 100;
        c = Math.round(c);

        const reasons = data.reasons || [];
        const flagCount = reasons.length;

        // DOMAIN
        if (domainSpan) {
            try {
                domainSpan.innerText = new URL(url).hostname.replace("www.", "");
            } catch {
                domainSpan.innerText = "Unknown Site";
            }
        }

        // STATUS
        if (statusDiv) {
            statusDiv.innerText = data.prediction.toUpperCase();
            statusDiv.className = `status-pill ${data.action.toLowerCase()}`;
        }

        // CONFIDENCE
        if (confidenceDiv) {
            confidenceDiv.innerText = `Risk: ${c}% • ${flagCount} flag${flagCount === 1 ? "" : "s"}`;
        }

        // BAR
        if (fill) {
            fill.style.width = c + "%";
            fill.style.transition = "width 0.5s ease";

            if (c < 35) fill.style.background = "#27ae60";
            else if (c < 75) fill.style.background = "#f39c12";
            else fill.style.background = "#e74c3c";
        }

        // ---------------------------
        // CLEAR OLD REASONS ✅ FIX
        // ---------------------------
        if (reasonsDiv) {
            reasonsDiv.innerHTML = "";
        }

        // ---------------------------
        // REASONS
        // ---------------------------
        if (reasons.length > 0 && reasonsDiv) {

            reasons.forEach(reason => {
                const div = document.createElement("div");
                div.className = `reason ${getLevel(reason)}`;
                div.textContent = reason;
                reasonsDiv.appendChild(div);
            });

        } else if (reasonsDiv) {

            if (c > 0) {
                reasonsDiv.innerHTML = `
                    <div class="reason low">
                        Minor risk indicators detected (low confidence)
                    </div>
                `;
            } else {
                reasonsDiv.innerHTML = `
                    <div class="safe-box">
                        ✓ No threats detected. This page appears secure.
                    </div>
                `;
            }
        }
    });
}

// ===========================
// INIT
// ===========================

document.addEventListener("DOMContentLoaded", () => {
    loadTheme();
    setupThemeToggle();
    renderAnalysis();
});

chrome.storage.onChanged.addListener((changes) => {
    if (changes.analysisResult) {
        renderAnalysis();
    }
});