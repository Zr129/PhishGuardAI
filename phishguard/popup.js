/**
 * popup.js — PhishGuard Popup
 *
 * Three classes, three responsibilities:
 *   ThemeManager    — dark/light mode persistence and toggling
 *   SeverityClassifier — maps a reason string to a severity level
 *   PopupRenderer   — reads storage and updates every DOM element
 */

"use strict";

// ─────────────────────────────────────────
// ThemeManager
// SRP: only knows about theme state
// ─────────────────────────────────────────

class ThemeManager {
    constructor(toggleBtnId = "theme-toggle") {
        this._btn = document.getElementById(toggleBtnId);
    }

    load() {
        chrome.storage.local.get("theme", res => {
            const theme = res.theme
                || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
            this._apply(theme);
        });
    }

    bindToggle() {
        if (!this._btn) return;
        this._btn.onclick = () => {
            const next = document.body.classList.contains("dark") ? "light" : "dark";
            chrome.storage.local.set({ theme: next });
            this._apply(next);
        };
    }

    _apply(theme) {
        const isDark = theme === "dark";
        document.body.classList.toggle("dark", isDark);
        if (this._btn) this._btn.innerText = isDark ? "☀️" : "🌙";
    }
}


// ─────────────────────────────────────────
// SeverityClassifier
// SRP: only knows how to classify a reason string
// OCP: add new keywords here without touching renderer
// ─────────────────────────────────────────

class SeverityClassifier {
    static HIGH_KEYWORDS   = ["password", "blacklist", "impersonation", "harvesting", "credential"];
    static MEDIUM_KEYWORDS = ["external", "ratio", "subdomain", "cloaked", "redirect", "iframe"];

    classify(reason) {
        const r = reason.toLowerCase();
        if (SeverityClassifier.HIGH_KEYWORDS.some(k => r.includes(k)))   return "high";
        if (SeverityClassifier.MEDIUM_KEYWORDS.some(k => r.includes(k))) return "medium";
        return "low";
    }
}


// ─────────────────────────────────────────
// PopupRenderer
// SRP: only knows how to update the popup DOM
// Depends on SeverityClassifier via constructor (DIP)
// ─────────────────────────────────────────

class PopupRenderer {
    constructor(classifier) {
        this._classifier = classifier;

        // Cache DOM refs once
        this._els = {
            status:     document.getElementById("status"),
            confidence: document.getElementById("confidence"),
            reasons:    document.getElementById("reasons"),
            domain:     document.getElementById("current-domain"),
            fill:       document.getElementById("confidence-fill"),
        };
    }

    render() {
        chrome.storage.local.get("analysisResult", res => {
            const wrapper = res.analysisResult;

            if (!wrapper?.data) {
                this._renderLoading();
                return;
            }

            const { data, url } = wrapper;

            if (data.prediction === "offline" || data.prediction === "error") {
                this._renderOffline();
                return;
            }

            this._renderResult(data, url);
        });
    }

    // ── States ──────────────────────────

    _renderLoading() {
        this._setStatus("ANALYSING...", "idle");
        this._setText("confidence", "Scanning website...");
        this._setBar(10, "#95a5a6");
        this._setHTML("reasons", `<div class="safe-box">🔍 Running analysis...</div>`);
    }

    _renderOffline() {
        this._setStatus("OFFLINE", "idle");
        this._setText("confidence", "Backend unavailable");
        this._setBar(0, "#95a5a6");
        this._setHTML("reasons", `<div class="safe-box">⚠️ Backend not connected</div>`);
    }

    _renderResult(data, url) {
        const confidence = Math.round(data.confidence); // backend returns 0–95 integer already
        const reasons    = data.reasons || [];

        this._renderDomain(url);
        this._setStatus(data.prediction.toUpperCase(), data.action.toLowerCase());
        this._setText("confidence", `Risk: ${confidence}% • ${reasons.length} flag${reasons.length === 1 ? "" : "s"}`);
        this._renderBar(confidence);
        this._renderReasons(reasons, confidence);
    }

    // ── DOM helpers ─────────────────────

    _renderDomain(url) {
        const el = this._els.domain;
        if (!el) return;
        try {
            el.innerText = new URL(url).hostname.replace("www.", "");
        } catch {
            el.innerText = "Unknown Site";
        }
    }

    _setStatus(text, cssClass) {
        const el = this._els.status;
        if (!el) return;
        el.innerText   = text;
        el.className   = `status-pill ${cssClass}`;
    }

    _setText(key, text) {
        const el = this._els[key];
        if (el) el.innerText = text;
    }

    _setHTML(key, html) {
        const el = this._els[key];
        if (el) el.innerHTML = html;
    }

    _setBar(widthPct, colour) {
        const el = this._els.fill;
        if (!el) return;
        el.style.width      = `${widthPct}%`;
        el.style.background = colour;
    }

    _renderBar(confidence) {
        const colour = confidence < 35 ? "#27ae60"
                     : confidence < 75 ? "#f39c12"
                     : "#e74c3c";
        const el = this._els.fill;
        if (!el) return;
        el.style.transition = "width 0.5s ease";
        this._setBar(confidence, colour);
    }

    _renderReasons(reasons, confidence) {
        const el = this._els.reasons;
        if (!el) return;

        el.innerHTML = "";

        if (reasons.length > 0) {
            reasons.forEach(reason => {
                const div       = document.createElement("div");
                div.className   = `reason ${this._classifier.classify(reason)}`;
                div.textContent = reason;
                el.appendChild(div);
            });
            return;
        }

        el.innerHTML = confidence > 0
            ? `<div class="reason low">Minor risk indicators detected (low confidence)</div>`
            : `<div class="safe-box">✓ No threats detected. This page appears secure.</div>`;
    }
}


// ─────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
    const theme    = new ThemeManager();
    const renderer = new PopupRenderer(new SeverityClassifier());

    theme.load();
    theme.bindToggle();
    renderer.render();

    // Re-render only when analysis data changes (not theme changes)
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === "local" && changes.analysisResult?.newValue) {
            renderer.render();
        }
    });
});
