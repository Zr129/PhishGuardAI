console.log("PHISHGUARD: BACKGROUND SERVICE WORKER BOOTED");

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // 1. TOP-LEVEL TRY-CATCH
    try {
        console.log("PHISHGUARD: Message received", message.type);

        if (message.type === "ANALYZE_PAGE") {
            const pageData = message.data;

            if (!pageData) {
                throw new Error("Received empty data payload from content script.");
            }

            // 2. NETWORK FETCH WITH INTERNAL CATCH
            fetch("http://127.0.0.1:8000/analyse", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(pageData)
            })
            .then(response => {
                if (!response.ok) throw new Error(`Server responded with status: ${response.status}`);
                return response.json();
            })
            .then(apiResponse => {
                // 3. STORAGE SYNC WITH ERROR CHECKING
                chrome.storage.local.set({
                    analysisResult: {
                        url: pageData.url,
                        data: apiResponse,
                        timestamp: Date.now()
                    }
                }, () => {
                    if (chrome.runtime.lastError) {
                        console.error("PHISHGUARD: Storage Sync Error:", chrome.runtime.lastError);
                    }
                    sendResponse(apiResponse);
                });
            })
            .catch(fetchError => {
                // This catches network issues (Server down, 404, 500)
                console.error("PHISHGUARD: Fetch/API Error:", fetchError.message);
                sendResponse({
                    action: "ALLOW",
                    prediction: "error",
                    reasons: ["Server communication failed"],
                    confidence: 0
                });
            });

            // Return true to keep the async channel alive
            return true; 
        }
    } catch (globalError) {
        // This catches logic errors (e.g., trying to access a property of null)
        console.error("PHISHGUARD: Global Service Worker Exception:", globalError);
        sendResponse({ action: "ERROR", reasons: ["Internal Extension Error"] });
        return false;
    }
});