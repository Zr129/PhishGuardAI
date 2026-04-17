/**
 * background.js — PhishGuard Service Worker
 *
 * Three classes, three responsibilities:
 *   APIClient      — handles all fetch communication with the backend
 *   ResultStore    — manages chrome.storage read/write
 *   MessageHandler — listens for extension messages, delegates to the above
 */

"use strict";

// ─────────────────────────────────────────
// APIClient
// SRP: only knows how to call the backend
// ─────────────────────────────────────────

class APIClient {
    static API_URL    = "http://127.0.0.1:8000/analyse";
    static TIMEOUT_MS = 3000;

    async analyse(pageData) {
        const controller = new AbortController();
        const timeout    = setTimeout(() => controller.abort(), APIClient.TIMEOUT_MS);

        try {
            const response = await fetch(APIClient.API_URL, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body:    JSON.stringify(pageData),
                signal:  controller.signal,
            });

            clearTimeout(timeout);

            if (!response.ok) {
                throw new Error(`Server responded with ${response.status}`);
            }

            return await response.json();

        } catch (err) {
            clearTimeout(timeout);
            const reason = err.name === "AbortError" ? "Request timed out" : "Backend unavailable";
            console.error("PHISHGUARD [APIClient]:", err.message);
            throw new Error(reason);
        }
    }
}


// ─────────────────────────────────────────
// ResultStore
// SRP: only knows how to persist/retrieve results
// ─────────────────────────────────────────

class ResultStore {
    save(url, data) {
        chrome.storage.local.set({
            analysisResult: { url, data, timestamp: Date.now() }
        });
    }

    saveError(url, reason) {
        this.save(url, {
            action:     "ERROR",
            prediction: "offline",
            confidence: 0,
            reasons:    [reason],
        });
    }
}


// ─────────────────────────────────────────
// MessageHandler
// Orchestrator: routes messages to APIClient + ResultStore
// OCP: new message types can be added without touching existing handlers
// ─────────────────────────────────────────

class MessageHandler {
    constructor(apiClient, store) {
        this._api   = apiClient;
        this._store = store;
    }

    listen() {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            const handler = this._getHandler(message.type);

            if (!handler) {
                console.warn("PHISHGUARD: Unknown message type:", message.type);
                return false;
            }

            handler(message, sendResponse);
            return true; // keep channel open for async response
        });
    }

    _getHandler(type) {
        const handlers = {
            ANALYZE_PAGE:          this._handleAnalysis.bind(this),
            IFRAME_THREAT_DETECTED: this._handleIframeThreat.bind(this),
        };
        return handlers[type] || null;
    }

    async _handleAnalysis(message, sendResponse) {
        const pageData = message.data;

        if (!pageData?.url || !pageData?.domain) {
            console.error("PHISHGUARD: Invalid payload");
            const fallback = { action: "ERROR", prediction: "offline", confidence: 0, reasons: ["Invalid payload"] };
            this._store.save(pageData?.url || "", fallback);
            sendResponse(fallback);
            return;
        }

        try {
            const result = await this._api.analyse(pageData);
            console.log("PHISHGUARD RESULT:", result);
            this._store.save(pageData.url, result);
            sendResponse(result);
        } catch (err) {
            console.error("PHISHGUARD [MessageHandler]:", err.message);
            this._store.saveError(pageData.url, err.message);
            sendResponse({
                action:     "ERROR",
                prediction: "offline",
                confidence: 0,
                reasons:    [err.message],
            });
        }
    }

    _handleIframeThreat(message, sendResponse) {
        console.warn("PHISHGUARD: Malicious iframe signal received");
        sendResponse({ received: true });
    }
}


// ─────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────

console.log("PHISHGUARD: Background service worker booted");

const handler = new MessageHandler(new APIClient(), new ResultStore());
handler.listen();
