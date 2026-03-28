console.log("BACKGROUND SERVICE WORKER BOOTED");
// Listen for messages from content scripts

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    console.log("Message received in background:", message);

    // Only handle analysis requests
    if (message.type === "ANALYZE_PAGE") {

        const features = message.features;

        // Call backend API
        fetch("http://127.0.0.1:8000/analyse", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(features)
        })
        .then(response => response.json())
        .then(data => {

            console.log("Backend response:", data);

            // Send result back to content.js
            sendResponse(data);

            // store globally 
            chrome.storage.local.set({
                analysisResult: {
                    url: features.url,
                    data: data
                }
            });

        })
        .catch(error => {

            console.error("Error contacting backend:", error);

            sendResponse({
                prediction: "error",
                confidence: 0
            });

        });

        // Required for async response
        return true;
    }
});