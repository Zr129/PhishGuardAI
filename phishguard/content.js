// Prevent script from running multiple times
if (window.hasRunPhishGuard) {
    console.log("Already ran, skipping...");
} else {
    window.hasRunPhishGuard = true;

    // Display warning banner
    function showWarningBanner(prediction, confidence) {
        const existingBanner = document.getElementById("phishguard-warning-banner");
        if (existingBanner) {
            existingBanner.remove();
        }

        const safeConfidence = typeof confidence === "number" ? confidence : 0;

        const banner = document.createElement("div");
        banner.id = "phishguard-warning-banner";

        // Banner styling
        banner.style.position = "fixed";
        banner.style.top = "0";
        banner.style.left = "0";
        banner.style.width = "100%";
        banner.style.padding = "12px";
        banner.style.zIndex = "2147483647";
        banner.style.fontSize = "14px";
        banner.style.fontWeight = "bold";
        banner.style.display = "flex";
        banner.style.justifyContent = "space-between";
        banner.style.alignItems = "center";
        banner.style.boxShadow = "0 2px 6px rgba(0,0,0,0.2)";
        banner.style.color = "white";
        banner.style.fontFamily = "Arial, sans-serif";

        // Set colour based on prediction
        if (prediction === "phishing") {
            banner.style.backgroundColor = "#e74c3c";
        } else {
            banner.style.backgroundColor = "#f39c12";
        }

        // Banner text
        const text = document.createElement("div");
        text.textContent = `${prediction.toUpperCase()} detected (${Math.round(safeConfidence * 100)}%)`;

        // Action buttons container
        const actions = document.createElement("div");
        actions.style.display = "flex";
        actions.style.alignItems = "center";
        actions.style.gap = "8px";

        // View details button
        const detailsBtn = document.createElement("button");
        detailsBtn.textContent = "View Details";
        detailsBtn.style.padding = "4px 8px";
        detailsBtn.style.cursor = "pointer";
        detailsBtn.style.border = "none";
        detailsBtn.style.borderRadius = "4px";

        detailsBtn.onclick = () => {
            alert("Click the PhishGuard extension icon to view full analysis.");
        };

        // Close banner button
        const closeBtn = document.createElement("button");
        closeBtn.textContent = "✖";
        closeBtn.style.padding = "4px 8px";
        closeBtn.style.cursor = "pointer";
        closeBtn.style.border = "none";
        closeBtn.style.borderRadius = "4px";

        closeBtn.onclick = () => banner.remove();

        // Append buttons
        actions.appendChild(detailsBtn);
        actions.appendChild(closeBtn);

        banner.appendChild(text);
        banner.appendChild(actions);

        // Safely inject banner into DOM
        const injectBanner = () => {
            if (!document.getElementById("phishguard-warning-banner")) {
                if (document.documentElement) {
                    document.documentElement.prepend(banner);
                } else if (document.body) {
                    document.body.prepend(banner);
                }
            }
        };

        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", injectBanner, { once: true });
        } else {
            injectBanner();
        }
    }

    // Extract clean domain from URL
    function getDomain(url) {
        try {
            return new URL(url).hostname.replace(/^www\./, "");
        } catch (error) {
            return "";
        }
    }

    // Main execution block
    (async () => {
        try {
            console.log("PhishGuard running...");

            const url = window.location.href;
            const domain = getDomain(url);
            const title = document.title || "";

            const knownBrands = ["paypal", "amazon", "google", "facebook"];

            let brandMismatch = false;
            let detectedBrand = null;

            // Detect brand mismatch between title and domain
            knownBrands.forEach((brand) => {
                if (title.toLowerCase().includes(brand) && !domain.includes(brand)) {
                    brandMismatch = true;
                    detectedBrand = brand;
                }
            });

            // Extract page features
            const forms = document.querySelectorAll("form");
            const passwordFields = document.querySelectorAll("input[type='password']");
            const scripts = document.querySelectorAll("script");
            const iframes = document.querySelectorAll("iframe");
            const hiddenElements = document.querySelectorAll("[type='hidden']");
            const anchors = document.querySelectorAll("a");

            let externalAnchors = 0;
            let emptyAnchors = 0;

            // Analyse anchor tags
            anchors.forEach((a) => {
                try {
                    const href = a.getAttribute("href");

                    if (!href || href.trim() === "" || href === "#" || href.startsWith("javascript")) {
                        emptyAnchors++;
                    } else {
                        const fullUrl = new URL(href, window.location.origin);
                        const linkDomain = fullUrl.hostname.replace(/^www\./, "");

                        if (linkDomain && linkDomain !== domain) {
                            externalAnchors++;
                        }
                    }
                } catch (error) {
                    console.log("Anchor parsing skipped:", error);
                }
            });

            // Build features object
            const features = {
                url,
                domain,
                title: title.toLowerCase(),
                numForms: forms.length,
                numPasswordFields: passwordFields.length,
                numScripts: scripts.length,
                numIframes: iframes.length,
                hiddenElements: hiddenElements.length,
                totalAnchors: anchors.length,
                externalAnchors,
                emptyAnchors,
                brandMismatch,
                detectedBrand: detectedBrand || "",
                timestamp: Date.now()
            };

            console.log("Extracted features:", features);

            // Send features to background.js
            chrome.runtime.sendMessage(
                {
                    type: "ANALYZE_PAGE",
                    features: features
                },
                (response) => {
                    if (chrome.runtime.lastError) {
                        console.error("Message error:", chrome.runtime.lastError.message);
                        return;
                    }

                    console.log("Received from background:", response);

                    if (!response) {
                        console.log("No response received.");
                        return;
                    }

                    const prediction = String(response.prediction || "").trim().toLowerCase();
                    const confidence = typeof response.confidence === "number" ? response.confidence : 0;

                    console.log("Prediction:", prediction);
                    console.log("Confidence:", confidence);

                    // Show warning banner if threat detected
                    if (prediction.includes("phishing") || prediction.includes("suspicious")) {
                        console.log("Showing banner...");
                        showWarningBanner(prediction, confidence);
                    } else {
                        console.log("No threat detected.");
                    }

                    // Store result for popup usage
                    chrome.storage.local.set({
                        analysisResult: {
                            url: url,
                            data: response
                        }
                    });
                }
            );
        } catch (error) {
            console.error("Content script error:", error);
        }
    })();
}