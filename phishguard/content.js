(async () => {
    // Prevent multiple injections
    if (window.hasRunPhishGuard) return;
    window.hasRunPhishGuard = true;

    // --- 1. UI COMPONENT: THE WARNING BANNER ---
    function injectWarningBanner(action, message) {
        const oldBanner = document.getElementById("phishguard-alert-banner");
        if (oldBanner) oldBanner.remove();

        const banner = document.createElement("div");
        banner.id = "phishguard-alert-banner";
        
        // Red for BLOCK, Orange for WARN
        const bgColor = action === "BLOCK" ? "#d93025" : "#f29900"; 

        Object.assign(banner.style, {
            position: "fixed", top: "0", left: "0", width: "100%", zIndex: "2147483647",
            padding: "14px 20px", backgroundColor: bgColor, color: "white",
            fontWeight: "bold", fontSize: "16px", fontFamily: "sans-serif",
            display: "flex", justifyContent: "space-between", alignItems: "center",
            boxShadow: "0 4px 12px rgba(0,0,0,0.3)"
        });

        banner.innerHTML = `
            <div>⚠️ <strong>PhishGuard Alert:</strong> ${message}</div>
            <button id="pg-close" style="background:none; border:none; color:white; font-size:22px; cursor:pointer; line-height:1;">&times;</button>
        `;

        document.documentElement.prepend(banner);
        document.getElementById("pg-close").onclick = () => banner.remove();
    }

    // --- 2. FEATURE EXTRACTION ENGINE ---
    function scrapeFeatures() {
        const url = window.location.href;
        const host = window.location.hostname.replace(/^www\./, "");
        const rawTitle = document.title || "No Title";
        const anchors = Array.from(document.querySelectorAll("a"));
        const forms = Array.from(document.querySelectorAll("form"));
        const totalAnchors = anchors.length;

        // 1. Link Analysis
        let externalLinks = 0;
        let emptyLinks = 0;

        anchors.forEach(a => {
            const href = a.getAttribute("href");
            if (!href || href === "#" || href.startsWith("javascript:")) {
                emptyLinks++;
            } else {
                try {
                    const linkHost = new URL(a.href, window.location.origin).hostname.replace(/^www\./, "");
                    if (linkHost !== host && linkHost !== "") externalLinks++;
                } catch(e) {}
            }
        });

        // 2. Credential Theft Check (Forms)
        let hasPass = !!document.querySelector("input[type='password']");
        let remoteAction = false;
        
        forms.forEach(f => {
            if (f.querySelector("input[type='password']")) {
                const action = f.getAttribute("action");
                if (action) {
                    try {
                        const actHost = new URL(action, window.location.href).hostname.replace(/^www\./, "");
                        if (actHost !== host) remoteAction = true;
                    } catch(e) { remoteAction = true; }
                }
            }
        });

        // 3. Brand Identification
        // We find the brand keyword here, but Python will decide if it's a mismatch
        const brands = ['paypal', 'amazon', 'microsoft', 'google', 'netflix', 'apple', 'ebay', 'facebook'];
        const foundBrand = brands.find(b => rawTitle.toLowerCase().includes(b)) || "";

        return {
            url: url,
            domain: host,
            title: rawTitle.substring(0, 200), // Sanitized: limit length
            is_https: window.location.protocol === "https:",
            has_password_field: hasPass,
            action_to_different_domain: remoteAction,
            ext_anchor_ratio: totalAnchors > 0 ? (externalLinks / totalAnchors) : 0,
            num_links_external: externalLinks,
            empty_anchors: emptyLinks,
            total_anchors: totalAnchors,
            brand_keyword: foundBrand, // Python uses this for Mismatch logic
            has_ip: /\d+\.\d+\.\d+\.\d+/.test(host)
        };
    }

    // --- 3. ANALYZE & SYNC ---
    async function performAnalysis() {
        const features = scrapeFeatures();
        
        chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", data: features }, (response) => {
            if (response) {
                // Save full response (reasons, confidence, etc) for the Popup to read
                chrome.storage.local.set({ 
                    analysisResult: { url: features.url, data: response } 
                });

                // Trigger UI with a clean, non-technical message
                if (response.action === "BLOCK" || response.action === "WARN") {
                    const displayMsg = "Warning: Likely Phishing or Suspicious Activity";
                    injectWarningBanner(response.action, displayMsg);
                }
            }
        });
    }

    // Initial Run
    performAnalysis();

    // Re-run if a password field is dynamically added (e.g., clicking 'Login' button)
    const observer = new MutationObserver((mutations) => {
        for (let mutation of mutations) {
            if (document.querySelector("input[type='password']")) {
                performAnalysis();
                observer.disconnect();
                break;
            }
        }
    });
    
    observer.observe(document.body, { childList: true, subtree: true });

})();