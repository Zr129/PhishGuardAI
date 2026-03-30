(async () => {
    if (window.hasRunPhishGuard) return;
    window.hasRunPhishGuard = true;

    // --- 1. UI COMPONENT: THE WARNING BANNER ---
    function injectWarningBanner(prediction, reason, confidence) {
        const oldBanner = document.getElementById("phishguard-alert-banner");
        if (oldBanner) oldBanner.remove();

        const banner = document.createElement("div");
        banner.id = "phishguard-alert-banner";
        
        // Red for BLOCK (Phishing), Orange for WARN (Suspicious)
        const isBlock = prediction.toUpperCase() === "BLOCK" || prediction.toLowerCase().includes("phish");
        const bgColor = isBlock ? "#d93025" : "#f29900"; 

        Object.assign(banner.style, {
            position: "fixed", top: "0", left: "0", width: "100%", zIndex: "2147483647",
            padding: "14px 20px", backgroundColor: bgColor, color: "white",
            fontWeight: "bold", fontSize: "15px", fontFamily: "Arial, sans-serif",
            display: "flex", justifyContent: "space-between", alignItems: "center",
            boxShadow: "0 4px 12px rgba(0,0,0,0.3)"
        });

        banner.innerHTML = `
            <div>⚠️ <strong>PhishGuard Alert:</strong> ${reason}</div>
            <button id="pg-close" style="background:none; border:none; color:white; font-size:20px; cursor:pointer;">&times;</button>
        `;

        document.documentElement.prepend(banner);
        document.getElementById("pg-close").onclick = () => banner.remove();
    }

    // --- 2. FEATURE EXTRACTION ENGINE ---
    function scrapeFeatures() {
        const url = window.location.href;
        const host = window.location.hostname.replace(/^www\./, "");
        const title = document.title.toLowerCase();
        const anchors = Array.from(document.querySelectorAll("a"));
        const forms = Array.from(document.querySelectorAll("form"));
        const totalAnchors = anchors.length;

        let externalLinks = 0;
        anchors.forEach(a => {
            try {
                const linkHost = new URL(a.href, window.location.origin).hostname.replace(/^www\./, "");
                if (linkHost !== host) externalLinks++;
            } catch(e) {}
        });

        let hasPass = !!document.querySelector("input[type='password']");
        let remoteAction = false;
        forms.forEach(f => {
            if (f.querySelector("input[type='password']")) {
                const action = f.getAttribute("action");
                try {
                    const actHost = new URL(action, window.location.href).hostname.replace(/^www\./, "");
                    if (actHost !== host) remoteAction = true;
                } catch(e) { remoteAction = true; }
            }
        });

        // Brand Mismatch Check (Deterministic Tier 2)
        const brands = ['paypal', 'amazon', 'microsoft', 'google', 'netflix'];
        const foundBrand = brands.find(b => title.includes(b)) || "";
        const mismatch = foundBrand !== "" && !host.includes(foundBrand);

        return {
            url: url,
            domain: host,
            is_https: window.location.protocol === "https:",
            has_password_field: hasPass,
            action_to_different_domain: remoteAction,
            ext_anchor_ratio: anchors.length > 0 ? (externalLinks / anchors.length) : 0,
            num_links_external: externalLinks,
            empty_anchors: anchors.filter(a => !a.getAttribute("href") || a.getAttribute("href") === "#").length,
            total_anchors: totalAnchors,
            brand_keyword_count: foundBrand ? 1 : 0,
            brand_mismatch: mismatch,
            has_ip: /\d+\.\d+\.\d+\.\d+/.test(host)
        };
    }

    // --- 3. ANALYZE & SYNC ---
    async function performAnalysis() {
        const features = scrapeFeatures();
        
        chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", data: features }, (response) => {
            if (response) {
                // IMPORTANT: Save to storage so Popup.js can see it
                chrome.storage.local.set({ 
                    analysisResult: { url: features.url, data: response } 
                });

                // Trigger UI if deterministic rules hit
                if (response.action === "BLOCK" || response.action === "WARN") {
                    injectWarningBanner(response.action, response.reasons[0], response.confidence);
                }
            }
        });
    }

    performAnalysis();

    const observer = new MutationObserver(() => {
        if (document.querySelector("input[type='password']")) {
            performAnalysis();
            observer.disconnect();
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });

})();