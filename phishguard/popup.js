/**
 * popup.js — PhishGuard Popup
 *
 * ThemeManager       — dark/light mode
 * SeverityClassifier — maps reason + tier to CSS class and icon
 * PopupRenderer      — reads storage, updates all DOM elements
 */

"use strict";

const MAX_FLAGS_DEFAULT = 3;

// ── ThemeManager ──────────────────────────────────────────────────────

class ThemeManager {
    constructor(btnId = "theme-toggle") {
        this._btn = document.getElementById(btnId);
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
        const dark = theme === "dark";
        document.body.classList.toggle("dark", dark);
        if (this._btn) this._btn.textContent = dark ? "☀️" : "🌙";
    }
}


// ── SeverityClassifier ────────────────────────────────────────────────

class SeverityClassifier {
    // Maps tier name → CSS class and icon
    static TIER_MAP = {
        "RULE":      { cls: "rule",      icon: "🚫", label: "Rule" },
        "HEURISTIC": { cls: "heuristic", icon: "⚠️", label: "Heuristic" },
        "ML":        { cls: "ml",        icon: "🤖", label: "ML" },
    };

    forTier(tier) {
        return SeverityClassifier.TIER_MAP[tier] || { cls: "info", icon: "ℹ️", label: "" };
    }
}


// ── PopupRenderer ─────────────────────────────────────────────────────

class PopupRenderer {
    constructor(classifier) {
        this._classifier = classifier;
        this._showAll    = false;

        this._els = {
            status:    document.getElementById("status"),
            domain:    document.getElementById("current-domain"),
            barFill:   document.getElementById("bar-fill"),
            barLabel:  document.getElementById("bar-label"),
            ringFill:  document.getElementById("ring-fill"),
            riskPct:   document.getElementById("risk-pct"),
            flags:     document.getElementById("flags"),
            flagCount: document.getElementById("flag-count"),
            showMore:  document.getElementById("show-more"),
            timeEl:    document.getElementById("analysis-time"),
            shield:    document.getElementById("shield-icon"),
        };

        // Bind show-more toggle
        if (this._els.showMore) {
            this._els.showMore.onclick = () => {
                this._showAll = !this._showAll;
                this._els.showMore.textContent = this._showAll ? "Show fewer" : "Show all flags";
                this.render();
            };
        }
    }

    render() {
        chrome.storage.local.get("analysisResult", res => {
            const wrapper = res.analysisResult;
            if (!wrapper?.data) { this._renderLoading(); return; }

            const { data, url, timestamp } = wrapper;
            if (data.prediction === "offline" || data.prediction === "error") {
                this._renderOffline();
                return;
            }

            this._renderResult(data, url, timestamp);
        });
    }

    // ── States ──────────────────────────────────────────────────────

    _renderLoading() {
        this._setStatus("IDLE", "idle");
        this._setDomain("Analysing...");
        this._setBar(0, null);
        this._setRing(0, null);
        this._setText("riskPct", "—");
        this._setText("barLabel", "Scanning...");
        this._setText("flagCount", "");
        this._setHTML("flags", `<div class="safe-msg">🔍 Running analysis...</div>`);
        this._els.showMore && (this._els.showMore.style.display = "none");
    }

    _renderOffline() {
        this._setStatus("OFFLINE", "idle");
        this._setDomain("—");
        this._setBar(0, null);
        this._setRing(0, null);
        this._setText("riskPct", "—");
        this._setText("barLabel", "Backend unavailable");
        this._setText("flagCount", "");
        this._setHTML("flags", `<div class="offline-msg">⚡ Start the backend server to enable protection</div>`);
        this._els.showMore && (this._els.showMore.style.display = "none");
    }

    _renderResult(data, url, timestamp) {
        const confidence     = Math.round(data.confidence);
        const taggedReasons  = data.tagged_reasons || [];
        const allReasons     = data.reasons || [];
        const action         = data.action.toLowerCase();
        const flagCount      = allReasons.length;

        // Domain
        this._setDomain(this._extractDomain(url));

        // Status pill
        this._setStatus(data.prediction.toUpperCase(), action);

        // Shield icon animation on action change
        if (this._els.shield) {
            this._els.shield.textContent = action === "block" ? "🚨"
                                         : action === "warn"  ? "⚠️"
                                         : "🛡️";
        }

        // Risk bar + ring
        const colour = this._riskColour(confidence);
        this._setBar(confidence, colour);
        this._setRing(confidence, colour);
        this._setText("riskPct", `${confidence}%`);
        this._setText("barLabel", `Risk: ${confidence}% · ${flagCount} flag${flagCount === 1 ? "" : "s"}`);

        // Timestamp
        if (this._els.timeEl && timestamp) {
            const mins = Math.round((Date.now() - timestamp) / 60000);
            this._els.timeEl.textContent = mins < 1 ? "just now" : `${mins}m ago`;
        }

        // Flags
        this._renderFlags(taggedReasons, allReasons, confidence);
    }

    // ── Flags ────────────────────────────────────────────────────────

    _renderFlags(taggedReasons, allReasons, confidence) {
        const el = this._els.flags;
        if (!el) return;

        el.innerHTML = "";

        // Build display list — prefer tagged reasons, fall back to plain strings
        const items = taggedReasons.length > 0
            ? taggedReasons
            : allReasons.map(r => ({ text: r, tier: "HEURISTIC" }));

        if (items.length === 0) {
            el.innerHTML = confidence > 0
                ? `<div class="flag info"><span class="flag-icon">ℹ️</span><span class="flag-text">Minor signals detected</span></div>`
                : `<div class="safe-msg">✓ No threats detected — this page appears secure.</div>`;
            this._els.showMore && (this._els.showMore.style.display = "none");
            this._setText("flagCount", "");
            return;
        }

        // Sort: RULE first, then HEURISTIC, then ML
        const order = { RULE: 0, HEURISTIC: 1, ML: 2 };
        const sorted = [...items].sort((a, b) =>
            (order[a.tier] ?? 9) - (order[b.tier] ?? 9)
        );

        const limit   = this._showAll ? sorted.length : MAX_FLAGS_DEFAULT;
        const visible = sorted.slice(0, limit);

        visible.forEach(item => {
            el.appendChild(this._buildFlag(item.text, item.tier));
        });

        // Show-more button
        const hasMore = sorted.length > MAX_FLAGS_DEFAULT;
        if (this._els.showMore) {
            this._els.showMore.style.display = hasMore ? "block" : "none";
            if (!this._showAll && hasMore) {
                this._els.showMore.textContent = `Show all ${sorted.length} flags`;
            }
        }

        this._setText("flagCount", `${sorted.length} flag${sorted.length === 1 ? "" : "s"}`);
    }

    _buildFlag(text, tier) {
        const meta = this._classifier.forTier(tier);

        const flag  = document.createElement("div");
        flag.className = `flag ${meta.cls}`;

        const icon  = document.createElement("span");
        icon.className   = "flag-icon";
        icon.textContent = meta.icon;

        const body  = document.createElement("div");
        body.className = "flag-body";

        const label = document.createElement("span");
        label.className   = "flag-text";
        label.textContent = text;

        body.appendChild(label);

        // Show tier badge only if there's a meaningful label
        if (meta.label) {
            const badge = document.createElement("span");
            badge.className   = "flag-badge";
            badge.textContent = meta.label;
            body.appendChild(badge);
        }

        flag.append(icon, body);
        return flag;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    _extractDomain(url) {
        try {
            return new URL(url).hostname.replace("www.", "") || "Unknown site";
        } catch {
            return "Unknown site";
        }
    }

    _riskColour(confidence) {
        if (confidence < 20) return "var(--safe)";
        if (confidence < 50) return "var(--warn)";
        return "var(--danger)";
    }

    _setDomain(text) {
        const el = this._els.domain;
        if (el) el.textContent = text;
    }

    _setStatus(text, cssClass) {
        const el = this._els.status;
        if (!el) return;
        el.textContent = text;
        el.className   = `pill ${cssClass}`;
    }

    _setText(key, text) {
        const el = this._els[key];
        if (el) el.textContent = text;
    }

    _setHTML(key, html) {
        const el = this._els[key];
        if (el) el.innerHTML = html;
    }

    _setBar(pct, colour) {
        const el = this._els.barFill;
        if (!el) return;
        el.style.width      = `${pct}%`;
        el.style.background = colour || "var(--border)";
    }

    _setRing(pct, colour) {
        const el = this._els.ringFill;
        if (!el) return;
        // SVG circumference for r=15.9 is ~99.9 ≈ 100
        const dash = (pct / 100) * 100;
        el.setAttribute("stroke-dasharray", `${dash} ${100 - dash}`);
        el.style.stroke = colour || "var(--border)";
    }
}


// ── Entry point ───────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
    const theme    = new ThemeManager();
    const renderer = new PopupRenderer(new SeverityClassifier());

    theme.load();
    theme.bindToggle();
    renderer.render();

    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === "local" && changes.analysisResult?.newValue) {
            renderer.render();
        }
    });
});
