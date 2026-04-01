(async () => {
    // Prevent multiple injections on the same page
    if (window.hasRunPhishGuard) return;
    window.hasRunPhishGuard = true;

    // --- 1. UI COMPONENT: THE WARNING BANNER ---
    function injectWarningBanner(action, message) {
        // Only inject the banner into the TOP frame to avoid multiple banners appearing
        if (window.top !== window.self) return;

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

        // Shift the webpage content down to make room for the banner
        document.documentElement.style.transition = "margin-top 0.3s ease-out";
        document.documentElement.style.marginTop = bannerHeight;

        const closeBtn = document.getElementById("pg-close");
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
        console.log("PhishGuard: Starting feature extraction...");
        
        const url = window.location.href;
        const host = window.location.hostname.replace(/^www\./, "");
        const rawTitle = document.title || "No Title";
        const anchors = Array.from(document.querySelectorAll("a"));
        const forms = Array.from(document.querySelectorAll("form"));
        const totalAnchors = anchors.length;

        let externalLinks = 0;
        let emptyLinks = 0;
        const rawLinks = [];
        let isHiddenSubmission = false;
        let remoteAction = false;

        anchors.forEach(a => {
            const href = a.getAttribute("href");
            
            if (href && href.startsWith("http")) {
                const safeLink = href.length > 1000 ? href.substring(0, 1000) : href;
                rawLinks.push(safeLink);

                try {
                    const linkUrl = new URL(a.href, window.location.origin);
                    const linkHost = linkUrl.hostname.replace(/^www\./, "");
                    if (linkHost !== host && linkHost !== "") externalLinks++;
                } catch(e) {}
            }

            if (!href || href === "#" || href.startsWith("javascript:")) {
                emptyLinks++;
            }
        });

        const hasPass = !!document.querySelector("input[type='password']");
        
        forms.forEach(f => {
            const formHasPass = !!f.querySelector("input[type='password']");
            const action = f.getAttribute("action");

            if (formHasPass) {
                // Check for Hidden Submission (Actionless form)
                if (!action || action === "#" || action === "" || action.startsWith("javascript:")) {
                    isHiddenSubmission = true;
                }

                // Check for Remote Action
                if (action) {
                    try {
                        const actHost = new URL(action, window.location.href).hostname.replace(/^www\./, "");
                        if (actHost !== host) remoteAction = true;
                    } catch(e) { 
                        remoteAction = true; 
                    }
                }
            }
        });

        // The Scraped Payload
        const payload = {
            url: url,
            domain: host,
            title: rawTitle.substring(0, 200),
            is_main_frame: window.top === window.self, // Detects if script is in an iframe
            is_https: window.location.protocol === "https:",
            has_password_field: hasPass,
            action_to_different_domain: remoteAction,
            is_hidden_submission: isHiddenSubmission,
            links: rawLinks,
            ext_anchor_ratio: totalAnchors > 0 ? (externalLinks / totalAnchors) : 0,
            num_links_external: externalLinks,
            empty_anchors: emptyLinks,
            total_anchors: totalAnchors,
            has_ip: /\d+\.\d+\.\d+\.\d+/.test(host)
        };

        console.log("PhishGuard: Features scraped successfully.", payload);
        return payload;
    }

    // --- 3. ANALYZE & SYNC ---
    async function performAnalysis() {
        const features = scrapeFeatures();
        
        chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", data: features }, (response) => {
            if (chrome.runtime.lastError) {
                console.log("PhishGuard: Backend communication error:", chrome.runtime.lastError.message);
                return;
            }

            if (response) {
                console.log("PhishGuard: Analysis received:", response.action);
                
                // Only the main frame should save to storage and show the banner
                if (window.top === window.self) {
                    chrome.storage.local.set({ 
                        analysisResult: { url: features.url, data: response } 
                    });

                    if (response.action === "BLOCK" || response.action === "WARN") {
                        const displayMsg = response.action === "BLOCK" 
                            ? "Warning: Likely Phishing Activity" 
                            : "Warning: Suspicious Activity Detected";
                        injectWarningBanner(response.action, displayMsg);
                    }
                } else if (response.action === "BLOCK") {
                    // If an iframe is malicious, tell the main frame to show the warning
                    chrome.runtime.sendMessage({ type: "IFRAME_THREAT_DETECTED", action: response.action });
                }
            }
        });
    }

    // Initial Execution
    performAnalysis();

    // Re-run analysis if a password field is added dynamically
    let debounceTimer;
    const observer = new MutationObserver(() => {
        if (document.querySelector("input[type='password']")) {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                console.log("PhishGuard: Login field detected, re-analyzing...");
                performAnalysis();
                observer.disconnect();
            }, 750); 
        }
    });
    
    observer.observe(document.body, { childList: true, subtree: true });

})();