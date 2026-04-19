/**
 * popup.js — PhishGuard popup
 *
 * ThemeManager      — dark/light mode
 * SeverityClassifier — tier → CSS class + icon
 * SettingsManager   — whitelist/blacklist CRUD, syncs to backend
 * PopupRenderer     — main analysis view
 * App               — view switcher, entry point
 */

"use strict";

const API_BASE = "http://127.0.0.1:8000";
const MAX_FLAGS = 3;


// ── ThemeManager ──────────────────────────────────────────────────────

class ThemeManager {
    constructor() { this._btn = document.getElementById("theme-toggle"); }

    load() {
        chrome.storage.local.get("theme", res => {
            const t = res.theme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
            this._apply(t);
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
        const sun  = document.getElementById("icon-sun");
        const moon = document.getElementById("icon-moon");
        if (sun)  sun.style.display  = dark ? "block" : "none";
        if (moon) moon.style.display = dark ? "none"  : "block";
    }
}


// ── SeverityClassifier ────────────────────────────────────────────────

// SVG icons for the verdict hero card
const VERDICT_ICONS = {
    idle:  '<svg viewBox="0 0 22 22" fill="none" style="width:22px;height:22px"><path d="M11 2L4 5.5v5.5c0 4.2 3 7.8 7 8.9 4-1.1 7-4.7 7-8.9V5.5L11 2z" fill="currentColor" opacity="0.25"/><path d="M11 2L4 5.5v5.5c0 4.2 3 7.8 7 8.9 4-1.1 7-4.7 7-8.9V5.5L11 2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 11l2 2 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    allow: '<svg viewBox="0 0 22 22" fill="none" style="width:22px;height:22px"><circle cx="11" cy="11" r="8.5" stroke="currentColor" stroke-width="1.5"/><path d="M7 11l3 3 5-5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    warn:  '<svg viewBox="0 0 22 22" fill="none" style="width:22px;height:22px"><path d="M11 3L2 19h18L11 3z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M11 9.5v4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="11" cy="16.5" r="0.9" fill="currentColor"/></svg>',
    block: '<svg viewBox="0 0 22 22" fill="none" style="width:22px;height:22px"><circle cx="11" cy="11" r="8.5" stroke="currentColor" stroke-width="1.5"/><path d="M7.5 7.5l7 7M14.5 7.5l-7 7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
    offline: '<svg viewBox="0 0 22 22" fill="none" style="width:22px;height:22px"><path d="M4 4l14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><path d="M7 7.5A7.5 7.5 0 0119 18M3 4.5A12 12 0 0118 19" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" opacity="0.45"/><circle cx="11" cy="19" r="1.2" fill="currentColor"/></svg>',
};

class SeverityClassifier {
    static ICONS = {
        RULE:      '<svg class="flag-icon" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.3"/><path d="M5 5l4 4M9 5l-4 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>',
        HEURISTIC: '<svg class="flag-icon" viewBox="0 0 14 14" fill="none"><path d="M7 2l5.5 10H1.5L7 2z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M7 6v3M7 10.5v.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>',
        ML:        '<svg class="flag-icon" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="2" stroke="currentColor" stroke-width="1.3"/><path d="M7 2v2M7 10v2M2 7h2M10 7h2M3.5 3.5l1.5 1.5M9 9l1.5 1.5M3.5 10.5L5 9M9 5l1.5-1.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>',
        INFO:      '<svg class="flag-icon" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.3"/><path d="M7 6.5v4M7 5v-.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>',
    };
    static MAP = {
        RULE:      { cls: "rule",      label: "Rule" },
        HEURISTIC: { cls: "heuristic", label: "Heuristic" },
        ML:        { cls: "ml",        label: "ML" },
    };
    forTier(tier)     { return SeverityClassifier.MAP[tier] || { cls: "info", label: "" }; }
    iconForTier(tier) { return SeverityClassifier.ICONS[tier] || SeverityClassifier.ICONS.INFO; }
}


// ── SettingsManager ───────────────────────────────────────────────────

class SettingsManager {

    constructor() {
        this._data = { blacklist: [], whitelist: [] };
    }

    async init() {
        await this._loadLocal();
        this._renderBoth();
        try {
            const remote = await this._apiFetch("GET", "/lists");
            this._data = remote;
            await this._saveLocal();
            this._renderBoth();
            this._setStatus("Synced", "saved");
        } catch {
            this._setStatus("Offline — local data", "");
        }
    }

    bindTabs() {
        document.querySelectorAll(".tab").forEach(tab => {
            tab.onclick = () => {
                document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
                document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
                tab.classList.add("active");
                document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
            };
        });
    }

    bindInputs() {
        const pairs = [
            ["whitelist", "whitelist-input", "whitelist-add", "whitelist-hint"],
            ["blacklist", "blacklist-input", "blacklist-add", "blacklist-hint"],
        ];
        pairs.forEach(([list, inputId, btnId, hintId]) => {
            const input = document.getElementById(inputId);
            const btn   = document.getElementById(btnId);
            btn.onclick = () => this._handleAdd(list, input, hintId);
            input.onkeydown = e => { if (e.key === "Enter") btn.click(); };
        });
    }

    async quickAdd(listName, domain) {
        if (!domain) return;
        await this._handleAddDomain(listName, domain,
            document.getElementById(`${listName}-hint`));
    }

    async _handleAdd(listName, input, hintId) {
        const domain = input.value.trim();
        if (!domain) { this._hint(hintId, "Enter a domain", ""); return; }
        const added = await this._handleAddDomain(listName, domain, document.getElementById(hintId));
        if (added) input.value = "";
    }

    async _handleAddDomain(listName, domain, hintEl) {
        this._setStatus("Saving...", "saving");
        try {
            await this._apiFetch("POST", `/lists/${listName}`, { domain });
            this._data[listName] = [...new Set([...this._data[listName], domain])].sort();
            const other = listName === "whitelist" ? "blacklist" : "whitelist";
            this._data[other] = this._data[other].filter(d => d !== domain);
            await this._saveLocal();
            this._renderBoth();
            if (hintEl) this._hint(hintEl.id, `${domain} added`, "ok");
            this._setStatus("Saved", "saved");
            return true;
        } catch (err) {
            if (hintEl) this._hint(hintEl.id, err.message, "");
            this._setStatus("Save failed", "");
            return false;
        }
    }

    async handleRemove(listName, domain) {
        this._setStatus("Saving...", "saving");
        try {
            await this._apiFetch("DELETE", `/lists/${listName}/${encodeURIComponent(domain)}`);
            this._data[listName] = this._data[listName].filter(d => d !== domain);
            await this._saveLocal();
            this._renderBoth();
            this._setStatus("Saved", "saved");
        } catch {
            this._setStatus("Remove failed", "");
        }
    }

    isWhitelisted(domain) { return this._data.whitelist.includes(domain); }
    isBlacklisted(domain) { return this._data.blacklist.includes(domain); }

    _renderBoth() {
        this._renderList("whitelist");
        this._renderList("blacklist");
        const b  = this._data.blacklist.length;
        const w  = this._data.whitelist.length;
        const el = document.getElementById("list-counts");
        if (el) el.textContent = `${w} trusted · ${b} blocked`;
    }

    _renderList(listName) {
        const wrap  = document.getElementById(`${listName}-list`);
        const items = this._data[listName] || [];
        wrap.innerHTML = "";
        if (!items.length) {
            wrap.innerHTML = `<div class="empty-msg">No domains added yet.</div>`;
            return;
        }
        items.forEach(domain => {
            const row   = document.createElement("div");
            row.className = "list-item";
            const label = document.createElement("span");
            label.className   = "list-item-domain";
            label.textContent = domain;
            const btn   = document.createElement("button");
            btn.className = "list-item-remove";
            btn.innerHTML = '<svg viewBox="0 0 12 12" fill="none" style="width:12px;height:12px"><path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
            btn.onclick   = () => this.handleRemove(listName, domain);
            row.append(label, btn);
            wrap.appendChild(row);
        });
    }

    async _apiFetch(method, path, body) {
        const opts = { method, headers: { "Content-Type": "application/json" } };
        if (body) opts.body = JSON.stringify(body);
        const res = await fetch(`${API_BASE}${path}`, opts);
        if (!res.ok) { const e = await res.json(); throw new Error(e.detail || "Error"); }
        return res.json();
    }

    async _loadLocal() {
        return new Promise(r => chrome.storage.local.get("userLists", res => {
            if (res.userLists) this._data = res.userLists;
            r();
        }));
    }

    async _saveLocal() {
        return new Promise(r => chrome.storage.local.set({ userLists: this._data }, r));
    }

    _hint(id, msg, cls) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = msg;
        el.className   = `add-hint ${cls}`;
        setTimeout(() => { el.textContent = ""; }, 3000);
    }

    _setStatus(msg, cls) {
        const el = document.getElementById("sync-status");
        if (el) { el.textContent = msg; el.className = cls; }
    }
}


// ── PopupRenderer ─────────────────────────────────────────────────────

class PopupRenderer {
    constructor(classifier, settings) {
        this._cls      = classifier;
        this._settings = settings;
        this._showAll  = false;
        this._domain   = "";

        this._els = {
            status:       document.getElementById("status"),
            domain:       document.getElementById("current-domain"),
            urlEl:        document.getElementById("current-url"),
            verdictLabel: document.getElementById("verdict-label"),
            hero:         document.getElementById("verdict-hero"),
            heroIcon:     document.getElementById("verdict-icon"),
            barFill:      document.getElementById("bar-fill"),
            barLabel:     document.getElementById("bar-label"),
            ringFill:     document.getElementById("ring-fill"),  // hidden — kept for compat
            riskPct:      document.getElementById("risk-pct"),
            flags:        document.getElementById("flags"),
            flagCount:    document.getElementById("flag-count"),
            showMore:     document.getElementById("show-more"),
            timeEl:       document.getElementById("analysis-time"),
            reportBtn:    document.getElementById("report-btn"),
            shield:       document.getElementById("shield-icon"),
            quickActions: document.getElementById("quick-actions"),
            btnTrust:     document.getElementById("btn-trust"),
            btnBlock:     document.getElementById("btn-block"),
        };

        if (this._els.showMore) {
            this._els.showMore.onclick = () => {
                this._showAll = !this._showAll;
                this._els.showMore.textContent = this._showAll ? "Show fewer" : `Show all flags`;
                this.render();
            };
        }

        if (this._els.btnTrust) {
            this._els.btnTrust.onclick = async () => {
                if (!this._domain) return;
                await this._settings.quickAdd("whitelist", this._domain);
                this.render();
            };
        }
        if (this._els.btnBlock) {
            this._els.btnBlock.onclick = async () => {
                if (!this._domain) return;
                await this._settings.quickAdd("blacklist", this._domain);
                this.render();
            };
        }
    }

    render() {
        chrome.storage.local.get("analysisResult", res => {
            const w = res.analysisResult;
            if (!w?.data)                                                          { this._loading(); return; }
            if (w.data.prediction === "offline" || w.data.prediction === "error") { this._offline(); return; }
            this._result(w.data, w.url, w.timestamp);
        });
    }

    _loading() {
        this._setHeroClass("idle");
        this._setHeroIcon("idle");
        this._setStatus("IDLE", "idle");
        this._setText("verdictLabel", "Analysing");
        this._setText("domain", "Scanning...");
        this._setText("urlEl", "");
        this._setBar(0);
        this._setText("riskPct", "—");
        this._setText("barLabel", "Initialising protection...");
        this._setText("flagCount", "");
        this._setHTML("flags",
            `<div class="safe-msg" style="color:var(--text-3)">
                <svg style="width:14px;height:14px;flex-shrink:0;animation:spin 1s linear infinite" viewBox="0 0 14 14" fill="none">
                    <circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.5" stroke-dasharray="20 10" opacity="0.4"/>
                    <path d="M7 2A5 5 0 1112 7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
                </svg>
                <span>Scanning page...</span>
            </div>`
        );
        if (this._els.showMore)     this._els.showMore.style.display     = "none";
        if (this._els.quickActions) this._els.quickActions.style.display = "none";
        if (this._els.reportBtn)    this._els.reportBtn.style.display    = "none";
    }

    _offline() {
        this._setHeroClass("idle");
        this._setHeroIcon("offline");
        this._setStatus("OFFLINE", "idle");
        this._setText("verdictLabel", "Offline");
        this._setText("domain", "—");
        this._setText("urlEl", "");
        this._setBar(0);
        this._setText("riskPct", "—");
        this._setText("barLabel", "Backend unavailable");
        this._setText("flagCount", "");
        this._setHTML("flags",
            `<div class="offline-msg">
                Backend server is not running.<br>
                <span style="font-size:11px;opacity:0.55">Start the backend to enable protection.</span>
            </div>`
        );
        if (this._els.showMore)     this._els.showMore.style.display     = "none";
        if (this._els.quickActions) this._els.quickActions.style.display = "none";
        if (this._els.reportBtn)    this._els.reportBtn.style.display    = "none";
    }

    _result(data, url, timestamp) {
        const conf    = Math.round(data.confidence);
        const tagged  = data.tagged_reasons || [];
        const reasons = data.reasons || [];
        const action  = data.action.toLowerCase();

        // Verdict text per action
        const labels = { block: "Threat Detected", warn: "Suspicious", allow: "Secure", error: "Offline" };

        try { this._domain = new URL(url).hostname.replace(/^www\./, ""); } catch { this._domain = ""; }

        // Only colour the hero for warn/block — allow stays neutral
        this._setHeroClass(action === 'allow' && tagged.length === 0 ? 'idle' : action);
        this._setHeroIcon(action);
        this._setText("verdictLabel", labels[action] || "Verdict");
        this._setText("domain", this._domain || "Unknown site");
        // Show truncated URL under domain
        if (this._els.urlEl) {
            const display = (url || "").replace(/^https?:\/\//, "").replace(/^www\./, "");
            this._els.urlEl.textContent = display.length > 55 ? display.substring(0, 55) + "…" : display;
            this._els.urlEl.title = url || "";  // full URL on hover
        }
        const pillLabels = { block: "BLOCKED", warn: "CAUTION", allow: "SAFE", safe: "SAFE" };
        this._setStatus(pillLabels[action] || data.prediction.toUpperCase(), action);

        if (this._els.shield) {
            this._els.shield.style.color = action === "block" ? "var(--danger)"
                                         : action === "warn"  ? "var(--warn)"
                                         :                      "var(--accent)";
        }

        this._setBar(conf);
        this._setText("riskPct", `${conf}%`);
        const flagTxt = reasons.length === 0 ? "No threats detected"
            : `${reasons.length} flag${reasons.length === 1 ? "" : "s"} · ${conf}% risk`;
        this._setText("barLabel", flagTxt);

        if (this._els.timeEl && timestamp) {
            const mins = Math.round((Date.now() - timestamp) / 60000);
            this._els.timeEl.textContent = mins < 1 ? "just now" : `${mins}m ago`;
        }

        if (this._els.quickActions && this._domain) {
            this._els.quickActions.style.display = "flex";
            const trusted    = this._settings.isWhitelisted(this._domain);
            const blocked    = this._settings.isBlacklisted(this._domain);
            const trustLabel = document.getElementById("btn-trust-label");
            const blockLabel = document.getElementById("btn-block-label");
            if (trustLabel) trustLabel.textContent = trusted ? "Trusted" : "Trust this site";
            if (blockLabel) blockLabel.textContent = blocked ? "Blocked" : "Block this site";
            this._els.btnTrust.disabled = trusted;
            this._els.btnBlock.disabled = blocked;
            this._els.btnTrust.classList.toggle("active", trusted);
            this._els.btnBlock.classList.toggle("active", blocked);
        }

        if (this._els.reportBtn) {
            this._els.reportBtn.style.display = "block";
            this._els.reportBtn.onclick = () => this._generateReport(data, url);
        }

        this._renderFlags(tagged, reasons, conf);
    }

    async _generateReport(data, url) {
        const btn = this._els.reportBtn;
        if (!btn) return;

        const lbl = document.getElementById("report-btn-label");
        if (lbl) lbl.textContent = "Generating...";
        btn.classList.add("loading");
        btn.disabled = true;

        try {
            const payload = {
                action:         data.action,
                prediction:     data.prediction,
                confidence:     data.confidence,
                reasons:        data.reasons || [],
                tagged_reasons: data.tagged_reasons || [],
            };

            const stored = await new Promise(r =>
                chrome.storage.local.get("lastPageData", res => r(res.lastPageData || {}))
            );
            Object.assign(payload, stored);
            payload.url    = payload.url    || url;
            payload.domain = payload.domain || new URL(url).hostname.replace("www.", "");
            payload.title  = payload.title  || "";

            const res = await fetch(`${API_BASE}/report`, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body:    JSON.stringify(payload),
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Report generation failed");
            }

            const contentType = res.headers.get("content-type") || "";
            const domain      = (payload.domain || "unknown").replace(/\./g, "_");
            const ts          = new Date().toISOString().slice(0, 10);

            let blobUrl, filename;
            if (contentType.includes("application/pdf")) {
                const pdfData = await res.arrayBuffer();
                const blob    = new Blob([pdfData], { type: "application/pdf" });
                blobUrl       = URL.createObjectURL(blob);
                filename      = `phishguard_${domain}_${ts}.pdf`;
            } else {
                const html = await res.text();
                const blob = new Blob([html], { type: "text/html" });
                blobUrl    = URL.createObjectURL(blob);
                filename   = `phishguard_${domain}_${ts}.html`;
            }

            await chrome.downloads.download({ url: blobUrl, filename, saveAs: false });

            if (lbl) lbl.textContent = "Report downloaded";
            btn.classList.remove("loading");
            setTimeout(() => {
                if (lbl) lbl.textContent = "Generate Security Report";
                btn.disabled = false;
            }, 2500);

        } catch (err) {
            console.error("PHISHGUARD [Report]:", err.message);
            if (lbl) lbl.textContent = err.message.includes("GROQ") ? "Set GROQ_API_KEY in .env" : "Report failed — try again";
            btn.classList.remove("loading");
            btn.disabled = false;
            setTimeout(() => { if (lbl) lbl.textContent = "Generate Security Report"; }, 3500);
        }
    }

    _renderFlags(tagged, reasons, conf) {
        const el = this._els.flags;
        if (!el) return;
        el.innerHTML = "";

        const items = tagged.length > 0
            ? tagged
            : reasons.map(r => ({ text: r, tier: "HEURISTIC" }));

        if (!items.length) {
            el.innerHTML = conf > 0
                ? `<div class="flag info"><svg class="flag-icon" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.3"/><path d="M7 6.5v4M7 5v-.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg><div class="flag-body"><span class="flag-text">Minor signals detected</span></div></div>`
                : `<div class="safe-msg"><svg style="width:14px;height:14px;flex-shrink:0" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.3"/><path d="M4.5 7l2 2 3-3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg><span>No threats detected</span></div>`;
            if (this._els.showMore) this._els.showMore.style.display = "none";
            this._setText("flagCount", "");
            return;
        }

        const order  = { RULE: 0, HEURISTIC: 1, ML: 2 };
        const sorted = [...items].sort((a, b) => (order[a.tier] ?? 9) - (order[b.tier] ?? 9));
        const limit  = this._showAll ? sorted.length : MAX_FLAGS;

        sorted.slice(0, limit).forEach(item => el.appendChild(this._buildFlag(item.text, item.tier)));

        const hasMore = sorted.length > MAX_FLAGS;
        if (this._els.showMore) {
            this._els.showMore.style.display = hasMore ? "block" : "none";
            if (!this._showAll && hasMore) {
                this._els.showMore.textContent = `Show all ${sorted.length} flags`;
            }
        }
        this._setText("flagCount", `${sorted.length} flag${sorted.length === 1 ? "" : "s"}`);
    }

    _buildFlag(text, tier) {
        const meta = this._cls.forTier(tier);
        const flag = document.createElement("div");
        flag.className = `flag ${meta.cls}`;

        const iconWrap = document.createElement("span");
        iconWrap.innerHTML = this._cls.iconForTier(tier);

        const body  = document.createElement("div");  body.className = "flag-body";
        const label = document.createElement("span"); label.className = "flag-text"; label.textContent = text;
        body.appendChild(label);

        if (meta.label) {
            const badge = document.createElement("span");
            badge.className = "flag-badge"; badge.textContent = meta.label;
            body.appendChild(badge);
        }
        flag.append(iconWrap, body);
        return flag;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    _setHeroClass(cls) {
        if (this._els.hero) this._els.hero.className = `verdict-hero ${cls}`;
    }

    _setHeroIcon(key) {
        if (this._els.heroIcon) this._els.heroIcon.innerHTML = VERDICT_ICONS[key] || VERDICT_ICONS.idle;
    }

    _setStatus(text, cls) {
        if (this._els.status) { this._els.status.textContent = text; this._els.status.className = `pill ${cls}`; }
    }

    _setText(key, val) { const e = this._els[key]; if (e) e.textContent = val; }
    _setHTML(key, html) { const e = this._els[key]; if (e) e.innerHTML = html; }

    // Bar: only width — CSS controls the colour inside the hero gradient
    _setBar(pct) {
        if (this._els.barFill) this._els.barFill.style.width = `${pct}%`;
    }

    // Ring: no-op — SVG ring removed from HTML, element kept hidden for compatibility
    _setRing(pct, col) { /* no-op — ring removed in v2 redesign */ }
}


// ── App — view switcher ───────────────────────────────────────────────

class App {
    constructor() {
        this._app      = document.querySelector(".app");
        this._theme    = new ThemeManager();
        this._settings = new SettingsManager();
        this._renderer = new PopupRenderer(new SeverityClassifier(), this._settings);
    }

    async init() {
        this._theme.load();
        this._theme.bindToggle();
        this._settings.bindTabs();
        this._settings.bindInputs();

        document.getElementById("settings-btn").onclick = async () => {
            this._app.classList.add("settings-open");
            this._app.style.minHeight = "500px";
            await this._settings.init();
        };
        document.getElementById("settings-back").onclick = () => {
            this._app.classList.remove("settings-open");
            this._app.style.minHeight = "";
            this._renderer.render();
        };

        this._renderer.render();

        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === "local" && changes.analysisResult?.newValue) {
                this._renderer.render();
            }
        });
    }
}

document.addEventListener("DOMContentLoaded", () => new App().init());
