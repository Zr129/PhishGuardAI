"use strict";

const API_BASE = "http://127.0.0.1:8000";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "ANALYZE_PAGE") {
        fetch(`${API_BASE}/analyse`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify(message.data),
        })
        .then(r => r.ok ? r.json() : Promise.reject(r.status))
        .then(result => {
            chrome.storage.local.set({
                analysisResult: {
                    data:      result,
                    url:       message.data.url,
                    timestamp: Date.now(),
                }
            });
            sendResponse(result);
        })
        .catch(() => {
            const offline = {
                action:         "ALLOW",
                prediction:     "offline",
                confidence:     0,
                reasons:        [],
                tagged_reasons: [],
            };
            chrome.storage.local.set({
                analysisResult: {
                    data:      offline,
                    url:       message.data.url,
                    timestamp: Date.now(),
                }
            });
            sendResponse(offline);
        });
        return true; // keep message channel open for async sendResponse
    }

    if (message.type === "OPEN_POPUP") {
        // Opens the popup when the user clicks "View details" in the banner
        chrome.action.openPopup?.();
    }

    if (message.type === "LEAVE_SITE") {
        // Open a new tab first (chrome://newtab won't trigger content.js,
        // so analysisResult stays in storage and the popup remains readable),
        // then close the phishing tab.
        const tabId = sender.tab?.id;
        chrome.tabs.create({}, () => {
            if (tabId !== undefined) chrome.tabs.remove(tabId);
        });
    }
});
