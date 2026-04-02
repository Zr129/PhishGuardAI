console.log("PHISHGUARD: BACKGROUND SERVICE WORKER BOOTED");

const API_URL = "http://127.0.0.1:8000/analyse";

// ===============================
// MAIN MESSAGE HANDLER
// ===============================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    try {
        console.log("PHISHGUARD: Message received →", message.type);

        // -------------------------------
        // ANALYSIS REQUEST
        // -------------------------------
        if (message.type === "ANALYZE_PAGE") {

            const pageData = message.data;

            // Validate payload
            if (!pageData || !pageData.url || !pageData.domain) {
                throw new Error("Invalid payload structure");
            }

            // Timeout controller (3s)
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 3000);

            fetch(API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(pageData),
                signal: controller.signal
            })

            // -------------------------------
            // SUCCESS RESPONSE
            // -------------------------------
            .then(response => {
                clearTimeout(timeout);

                if (!response.ok) {
                    throw new Error(`Server responded with ${response.status}`);
                }

                return response.json();
            })

            .then(apiResponse => {

                console.log("PHISHGUARD RESULT:", apiResponse);

                // ✅ ALWAYS SAVE RESULT
                chrome.storage.local.set({
                    analysisResult: {
                        url: pageData.url,
                        data: apiResponse,
                        timestamp: Date.now()
                    }
                });

                sendResponse(apiResponse);
            })

            // -------------------------------
            // ERROR HANDLING (CRITICAL FIX)
            // -------------------------------
            .catch(fetchError => {
                clearTimeout(timeout);

                let errorMsg = "Backend unavailable";

                if (fetchError.name === "AbortError") {
                    console.error("PHISHGUARD: Request timed out");
                    errorMsg = "Request timed out";
                } else {
                    console.error("PHISHGUARD: Fetch/API Error:", fetchError.message);
                }

                const fallback = {
                    action: "ERROR",
                    prediction: "offline",
                    confidence: 0,
                    reasons: [errorMsg]
                };

                // ✅ THIS FIXES YOUR UI STUCK ISSUE
                chrome.storage.local.set({
                    analysisResult: {
                        url: pageData.url,
                        data: fallback,
                        timestamp: Date.now()
                    }
                });

                sendResponse(fallback);
            });

            // Required for async response
            return true;
        }

        // -------------------------------
        // IFRAME ALERT (OPTIONAL)
        // -------------------------------
        if (message.type === "IFRAME_THREAT_DETECTED") {
            console.warn("PHISHGUARD: Malicious iframe detected");
        }

    } catch (globalError) {

        console.error("PHISHGUARD: Global Exception:", globalError);

        const fallback = {
            action: "ERROR",
            prediction: "offline",
            confidence: 0,
            reasons: ["Internal extension error"]
        };

        sendResponse(fallback);
        return false;
    }
});