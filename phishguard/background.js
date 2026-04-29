"use strict";

const API_BASE = "http://127.0.0.1:8000";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    if (message.type === "ANALYZE_PAGE") {
        const pageData = message.data;

        // Guard: only save results from the main frame to storage.
        // content.js already prevents iframes from sending messages via the
        // entry-point guard (window === window.top), but this is a defence-in-
        // depth check in case any non-main-frame message does reach here.
        // Saves the popup from showing a reCAPTCHA or payment widget domain
        // instead of the page the user is actually on.
        const isMainFrame = pageData?.is_main_frame !== false;

        fetch(`${API_BASE}/analyse`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify(pageData),
        })
        .then(r => r.ok ? r.json() : Promise.reject(r.status))
        .then(result => {
            if (isMainFrame) {
                chrome.storage.local.set({
                    analysisResult: {
                        data:      result,
                        url:       pageData.url,
                        timestamp: Date.now(),
                    }
                });
            }
            sendResponse(result);
        })
        .catch(() => {
            const offline = {
                action:         "ALLOW",
                prediction:     "offline",
                confidence:     0,
                reasons:        [],
                tagged_reasons: [],
                url:            pageData?.url    || "",
                domain:         pageData?.domain || "",
            };
            if (isMainFrame) {
                chrome.storage.local.set({
                    analysisResult: {
                        data:      offline,
                        url:       pageData?.url || "",
                        timestamp: Date.now(),
                    }
                });
            }
            sendResponse(offline);
        });

        return true; // keep message channel open for async sendResponse
    }

    if (message.type === "OPEN_POPUP") {
        chrome.action.openPopup?.();
    }

    if (message.type === "LEAVE_SITE") {
        const tabId = sender.tab?.id;
        chrome.tabs.create({}, () => {
            if (tabId !== undefined) chrome.tabs.remove(tabId);
        });
    }
});
