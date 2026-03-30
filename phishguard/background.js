console.log("PHISHGUARD: BACKGROUND SERVICE WORKER BOOTED");

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log("Message received in background:", message);

    if (message.type === "ANALYZE_PAGE") {
        // FIX: Match the key 'data' sent from content.js
        const pageData = message.data;

        // background.js
        console.log("SENDING TO PYTHON:", JSON.stringify(pageData, null, 2));

        if (!pageData) {
            console.error("No data payload found in message");
            return false;
        }

        // Call deterministic backend
        fetch("http://127.0.0.1:8000/analyse", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(pageData)
        })
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        })
        .then(apiResponse => {
            console.log("Backend verdict:", apiResponse);

            // 1. Save to storage for the Popup.js to read
            chrome.storage.local.set({
                analysisResult: {
                    url: pageData.url,
                    data: apiResponse
                }
            }, () => {
                // 2. Once saved, send the response back to content.js to trigger the banner
                sendResponse(apiResponse);
            });
        })
        .catch(error => {
            console.error("PhishGuard Backend Error:", error);
            sendResponse({
                action: "ALLOW",
                prediction: "error",
                reasons: ["Could not connect to analysis server"],
                confidence: 0
            });
        });

        return true; // Keep the message channel open for the async fetch
    }
});