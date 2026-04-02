(async () => {
    if (window.hasRunPhishGuard) return;
    window.hasRunPhishGuard = true;

    // ---------------------------
    // 1. WARNING BANNER
    // ---------------------------
    function injectWarningBanner(action, message) {
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
            padding: '0 20px'
        });

        banner.innerHTML = `
            <div style="flex-grow: 1; text-align: center;">
                ${action === "BLOCK" ? "🚫" : "⚠️"}
                <strong>PhishGuard:</strong> ${message}
            </div>
            <button id="pg-close" style="margin-left:20px;">&times;</button>
        `;

        document.documentElement.prepend(banner);
        document.documentElement.style.marginTop = bannerHeight;

        document.getElementById("pg-close").onclick = () => {
            banner.remove();
            document.documentElement.style.marginTop = "0";
        };
    }

    // ---------------------------
    // 2. FEATURE EXTRACTION
    // ---------------------------
    function scrapeFeatures() {
        const url = window.top.location.href;
        const host = window.location.hostname.replace(/^www\./, "");
        const title = (document.title || "").substring(0, 200);

        // ---------------------------
        // URL FEATURES
        // ---------------------------
        const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

        const subdomains = host.split(".");
        const subdomainCount = subdomains.length > 2 ? subdomains.length - 2 : 0;

        const hasDashes = host.includes("-");

        // ---------------------------
        // LINKS
        // ---------------------------
        const anchors = Array.from(document.querySelectorAll("a"));
        const totalAnchors = anchors.length;

        let emptyLinks = 0;
        const rawLinks = [];

        anchors.forEach(a => {
            const href = a.getAttribute("href");

            if (!href || href === "#" || href.startsWith("javascript:")) {
                emptyLinks++;
                return;
            }

            if (href.startsWith("http")) {
                rawLinks.push(href.length > 1000 ? href.substring(0, 1000) : href);
            }
        });

        // ---------------------------
        // FORMS
        // ---------------------------
        const forms = Array.from(document.querySelectorAll("form"));
        const hasPassword = !!document.querySelector("input[type='password']");

        let isHiddenSubmission = false;
        let remoteAction = false;

        forms.forEach(f => {
            const formHasPass = !!f.querySelector("input[type='password']");
            if (!formHasPass) return;

            const action = f.getAttribute("action");

            // Hidden submission
            if (!action || action === "#" || action === "" || action.startsWith("javascript:")) {
                isHiddenSubmission = true;
            }

            // JS submission
            if (f.getAttribute("onsubmit")) {
                isHiddenSubmission = true;
            }

            // External form action
            if (action) {
                try {
                    const actHost = new URL(action, window.location.href)
                        .hostname.replace(/^www\./, "");

                    if (actHost !== host && actHost !== "") {
                        remoteAction = true;
                    }
                } catch {
                    remoteAction = true;
                }
            }
        });

        return {
            url: url,
            domain: host,
            title: title,
            is_main_frame: window.top === window.self,
            is_https: window.location.protocol === "https:",
            has_password_field: hasPassword,

            // Form behaviour
            is_hidden_submission: isHiddenSubmission,
            action_to_different_domain: remoteAction,

            // Link data
            links: rawLinks,
            empty_anchors: emptyLinks,
            total_anchors: totalAnchors,

            // URL features
            has_ip: isIP,
            subdomain_count: subdomainCount,
            has_domain_dashes: hasDashes
        };
    }

    // ---------------------------
    // 3. ANALYSIS
    // ---------------------------
    function performAnalysis() {
        const features = scrapeFeatures();

        chrome.runtime.sendMessage(
            { type: "ANALYZE_PAGE", data: features },
            (response) => {
                if (!response) return;

                if (window.top === window.self) {
                    chrome.storage.local.set({
                        analysisResult: { url: features.url, data: response }
                    });

                    if (response.action === "BLOCK" || response.action === "WARN") {
                        const msg = response.action === "BLOCK"
                            ? "Likely phishing activity"
                            : "Suspicious activity detected";

                        injectWarningBanner(response.action, msg);
                    }
                }
            }
        );
    }

    // ---------------------------
    // RUN
    // ---------------------------
    performAnalysis();

    // Detect dynamic login forms
    let debounceTimer;
    const observer = new MutationObserver(() => {
        if (document.querySelector("input[type='password']")) {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                performAnalysis();
                observer.disconnect();
            }, 700);
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

})();