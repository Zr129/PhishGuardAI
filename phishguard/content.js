(async () => {
    // Prevent multiple injections
    if (window.hasRunPhishGuard) return;
    window.hasRunPhishGuard = true;

    // --- 1. UI COMPONENT: THE WARNING BANNER ---
    function injectWarningBanner(action, message) {
        const oldBanner = document.getElementById("phishguard-alert-banner");
        if (oldBanner) {
            document.documentElement.style.marginTop = "0";
            oldBanner.remove();
        }

        const banner = document.createElement("div");
        banner.id = "phishguard-alert-banner";
        
        const bgColor = action === "BLOCK" ? "#d93025" : "#f29900"; 
        const textColor = action === "BLOCK" ? "#ffffff" : "#000000";
        const bannerHeight = "80px"; 

        Object.assign(banner.style, {
            position: 'fixed',
            top: '0',
            left: '0',
            width: '100%',
            height: bannerHeight,
            zIndex: '2147483647',
            backgroundColor: bgColor,
            color: textColor,
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            fontWeight: 'bold',
            fontSize: '18px',
            fontFamily: "'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
            boxShadow: '0 4px 15px rgba(0,0,0,0.4)',
            boxSizing: 'border-box',
            padding: '0 20px',
            transition: 'transform 0.3s ease-out'
        });

        banner.innerHTML = `
            <div style="flex-grow: 1; text-align: center; display: flex; align-items: center; justify-content: center; gap: 12px;">
                <span style="font-size: 24px;">${action === "BLOCK" ? "🚫" : "⚠️"}</span>
                <span><strong>PhishGuard Alert:</strong> ${message}</span>
            </div>
            <button id="pg-close" style="
                background: rgba(0,0,0,0.1); 
                border: 1px solid rgba(0,0,0,0.2); 
                color: ${textColor}; 
                border-radius: 4px;
                padding: 5px 12px;
                font-size: 20px; 
                cursor: pointer; 
                transition: background 0.2s;
                margin-left: 20px;
            ">&times;</button>
        `;

        document.documentElement.prepend(banner);

        // PUSH DOWN THE CONTENT
        document.documentElement.style.transition = "margin-top 0.3s ease-out";
        document.documentElement.style.marginTop = bannerHeight;

        const closeBtn = document.getElementById("pg-close");
        closeBtn.onmouseover = () => closeBtn.style.background = "rgba(0,0,0,0.2)";
        closeBtn.onmouseout = () => closeBtn.style.background = "rgba(0,0,0,0.1)";
        
        closeBtn.onclick = () => {
            banner.style.transform = "translateY(-100%)"; 
            setTimeout(() => {
                banner.remove();
                document.documentElement.style.marginTop = "0";
            }, 300);
        };
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
        const rawLinks = [];

        anchors.forEach(a => {
            const href = a.getAttribute("href");
            
            // Collect raw URLs for Python TLDextract processing
            if (href && href.startsWith("http")) {
                rawLinks.push(a.href);
            }

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
        const brands = ['paypal', 'amazon', 'microsoft', 'google', 'netflix', 'apple', 'ebay', 'facebook', 'paloalto'];
        const foundBrand = brands.find(b => rawTitle.toLowerCase().includes(b)) || "";

        return {
            url: url,
            domain: host,
            title: rawTitle.substring(0, 200),
            is_https: window.location.protocol === "https:",
            has_password_field: hasPass,
            action_to_different_domain: remoteAction,
            links: rawLinks, // CRITICAL: Python needs this list for TLD-aware analysis
            ext_anchor_ratio: totalAnchors > 0 ? (externalLinks / totalAnchors) : 0,
            num_links_external: externalLinks,
            empty_anchors: emptyLinks,
            total_anchors: totalAnchors,
            brand_keyword: foundBrand, 
            has_ip: /\d+\.\d+\.\d+\.\d+/.test(host)
        };
    }

    // --- 3. ANALYZE & SYNC ---
    async function performAnalysis() {
        const features = scrapeFeatures();
        
        chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", data: features }, (response) => {
            if (response) {
                // Save for Popup
                chrome.storage.local.set({ 
                    analysisResult: { url: features.url, data: response } 
                });

                // Trigger UI
                if (response.action === "BLOCK" || response.action === "WARN") {
                    const displayMsg = response.action === "BLOCK" 
                        ? "Warning: Likely Phishing Activity" 
                        : "Warning: Suspicious Activity Detected";
                    injectWarningBanner(response.action, displayMsg);
                }
            }
        });
    }

    // Initial Run
    performAnalysis();

    // Re-run if a password field is dynamically added
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