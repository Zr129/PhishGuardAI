/**
 * content.js — PhishGuard Content Script
 *
 * FeatureExtractor  — scrapes all PhiUSIIL-aligned page features
 * WarningBanner     — manages the injected DOM alert banner
 * PageAnalyser      — orchestrates extraction → messaging → banner
 *
 * Security hardening:
 *   - Banner uses textContent not innerHTML for user-facing strings
 *   - URL capped at 2048 chars before sending
 *   - Links capped at 500, each truncated to 1000 chars
 *   - All DOM reads wrapped in try/catch
 */

"use strict";

// ─────────────────────────────────────────
// FeatureExtractor
// ─────────────────────────────────────────

class FeatureExtractor {

    extract() {
        return {
            ...this._getPageMeta(),
            ...this._getFormContext(),
            ...this._getLinkContext(),
            ...this._getPageContent(),
        };
    }

    _getPageMeta() {
        const host       = window.location.hostname.replace(/^www\./, "");
        const subdomains = host.split(".");
        let rawUrl;
        try { rawUrl = window.top.location.href; } catch { rawUrl = window.location.href; }

        return {
            // Cap URL length — validated server-side too
            url:           rawUrl.length > 2048 ? rawUrl.substring(0, 2048) : rawUrl,
            domain:        host,
            title:         (document.title || "").substring(0, 200),
            is_https:      window.location.protocol === "https:",
            is_main_frame: window.top === window.self,

            // PhiUSIIL features
            is_responsive:            !!document.querySelector("meta[name='viewport']"),
            has_favicon:              !!document.querySelector("link[rel~='icon']"),
            has_robots:               !!document.querySelector("meta[name='robots']"),
            has_description:          !!document.querySelector("meta[name='description']"),
            has_title:                document.title.trim().length > 0,
            domain_title_match_score: this._tokenOverlap(host, document.title),
            url_title_match_score:    this._tokenOverlap(rawUrl, document.title),
        };
    }

    _getFormContext() {
        const host = window.location.hostname.replace(/^www\./, "");
        let isHiddenSubmission      = false;
        let actionToDifferentDomain = false;

        try {
            document.querySelectorAll("form").forEach(form => {
                if (!form.querySelector("input[type='password']")) return;
                const action = form.getAttribute("action");

                if (!action || action === "#" || action === "" || action.startsWith("javascript:")) {
                    isHiddenSubmission = true;
                }
                if (form.getAttribute("onsubmit")) {
                    isHiddenSubmission = true;
                }
                if (action) {
                    try {
                        const actionHost = new URL(action, window.location.href)
                            .hostname.replace(/^www\./, "");
                        if (actionHost && actionHost !== host) actionToDifferentDomain = true;
                    } catch {
                        actionToDifferentDomain = true;
                    }
                }
            });
        } catch { /* DOM access may fail in sandboxed frames */ }

        return {
            has_password_field:         !!document.querySelector("input[type='password']"),
            is_hidden_submission:       isHiddenSubmission,
            action_to_different_domain: actionToDifferentDomain,
            has_submit_button: !!(
                document.querySelector("input[type='submit']") ||
                document.querySelector("button[type='submit']") ||
                document.querySelector("button:not([type])")
            ),
            has_hidden_fields: !!document.querySelector("input[type='hidden']"),
        };
    }

    _getLinkContext() {
        const host   = window.location.hostname.replace(/^www\./, "");
        const SOCIAL = new Set([
            "facebook.com","twitter.com","x.com","instagram.com",
            "linkedin.com","youtube.com","tiktok.com","reddit.com",
        ]);

        let emptyAnchors = 0;
        let selfRef      = 0;
        let hasSocialNet = false;
        const links      = [];

        try {
            const anchors = Array.from(document.querySelectorAll("a"));

            anchors.forEach(a => {
                const href = a.getAttribute("href");
                if (!href || href === "#" || href.startsWith("javascript:")) {
                    emptyAnchors++;
                    return;
                }
                if (href.startsWith("http")) {
                    // Cap at 500 links, each truncated to 1000 chars
                    if (links.length < 500) {
                        links.push(href.length > 1000 ? href.substring(0, 1000) : href);
                    }
                    try {
                        const linkHost = new URL(href).hostname.replace(/^www\./, "");
                        if (linkHost === host) selfRef++;
                        if (SOCIAL.has(linkHost)) hasSocialNet = true;
                    } catch { /* ignore malformed */ }
                }
            });

            return {
                links,
                empty_anchors:  emptyAnchors,
                total_anchors:  anchors.length,
                no_of_self_ref: selfRef,
                has_social_net: hasSocialNet,
            };
        } catch {
            return { links: [], empty_anchors: 0, total_anchors: 0, no_of_self_ref: 0, has_social_net: false };
        }
    }

    _getPageContent() {
        try {
            const bodyText  = (document.body?.innerText || "").toLowerCase();
            const BANK_KW   = ["bank","credit","debit","account","finance","loan","wire transfer"];
            const PAY_KW    = ["payment","pay now","checkout","billing","invoice","transaction"];
            const CRYPTO_KW = ["bitcoin","crypto","ethereum","wallet","blockchain","nft"];

            return {
                has_bank_keywords:   BANK_KW.some(k   => bodyText.includes(k)),
                has_pay_keywords:    PAY_KW.some(k    => bodyText.includes(k)),
                has_crypto_keywords: CRYPTO_KW.some(k => bodyText.includes(k)),
                has_copyright: bodyText.includes("©") || bodyText.includes("copyright"),
                no_of_images:  document.querySelectorAll("img").length,
                no_of_css:     document.querySelectorAll("link[rel='stylesheet']").length,
                no_of_js:      document.querySelectorAll("script[src]").length,

                // Auto-download: any <a download> pointing to an executable/archive
                has_auto_download: Array.from(document.querySelectorAll("a[download]"))
                    .some(a => /\.(exe|zip|msi|dmg|pkg|bat|cmd|ps1|vbs|jar)$/i.test(a.href)),

                // Meta refresh: redirect tag in <head>
                has_meta_refresh: !!document.querySelector("meta[http-equiv='refresh']"),

                // Suspicious scripts: many inline scripts but zero external scripts
                // Phishing pages often inline everything to avoid external requests
                has_suspicious_scripts: (() => {
                    const inline   = document.querySelectorAll("script:not([src])").length;
                    const external = document.querySelectorAll("script[src]").length;
                    return inline > 5 && external === 0;
                })(),
            };
        } catch {
            return {
                has_bank_keywords: false, has_pay_keywords: false, has_crypto_keywords: false,
                has_copyright: false, no_of_images: 0, no_of_css: 0, no_of_js: 0,
                has_auto_download: false, has_meta_refresh: false, has_suspicious_scripts: false,
            };
        }
    }
}

// ─────────────────────────────────────────
// WarningBanner
// Security: all user-facing strings via textContent, SVG via createElementNS
// ─────────────────────────────────────────

class WarningBanner {
    static BANNER_ID = "phishguard-banner";
    static STYLE_ID  = "phishguard-banner-style";

    constructor() {
        this._timer = null;
    }

    show(action, domain) {
        if (window.top !== window.self) return;
        this._removeExisting();
        this._injectStyles();
        const banner = this._build(action, domain);
        document.documentElement.prepend(banner);
        // Double rAF ensures transform transition fires after element is in DOM
        requestAnimationFrame(() => requestAnimationFrame(() => {
            banner.style.transform = "translateY(0)";
        }));
        document.documentElement.style.marginTop = "56px";
        if (action !== "BLOCK") {
            this._startCountdown(banner);
        }
    }

    dismiss() {
        clearInterval(this._timer);
        this._timer = null;
        const banner = document.getElementById(WarningBanner.BANNER_ID);
        if (banner) {
            banner.style.transform = "translateY(-100%)";
            setTimeout(() => this._removeExisting(), 300);
        } else {
            this._removeExisting();
        }
        document.documentElement.style.marginTop = "";
    }

    _removeExisting() {
        document.getElementById(WarningBanner.BANNER_ID)?.remove();
        clearInterval(this._timer);
        this._timer = null;
    }

    _injectStyles() {
        if (document.getElementById(WarningBanner.STYLE_ID)) return;
        const style = document.createElement("style");
        style.id = WarningBanner.STYLE_ID;
        style.textContent = [
            "#phishguard-banner {",
            "  position:fixed;top:0;left:0;right:0;z-index:2147483647;",
            "  height:56px;display:flex;align-items:center;gap:10px;padding:0 14px;",
            "  transform:translateY(-100%);",
            "  transition:transform 0.28s cubic-bezier(0.4,0,0.2,1);",
            "  font-family:-apple-system,'Segoe UI',system-ui,sans-serif;",
            "}",
            "#phishguard-banner.block{background:#1a0505;border-bottom:1px solid rgba(239,68,68,0.4);}",
            "#phishguard-banner.warn{background:#1c1505;border-bottom:1px solid rgba(234,179,8,0.4);}",
            "#phishguard-banner .pg-icon-circle{",
            "  width:32px;height:32px;border-radius:50%;flex-shrink:0;",
            "  display:flex;align-items:center;justify-content:center;",
            "}",
            "#phishguard-banner.block .pg-icon-circle{background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.3);}",
            "#phishguard-banner.warn  .pg-icon-circle{background:rgba(234,179,8,0.12);border:1px solid rgba(234,179,8,0.3);}",
            "#phishguard-banner .pg-text{flex:1;min-width:0;display:flex;flex-direction:column;gap:1px;}",
            "#phishguard-banner .pg-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;}",
            "#phishguard-banner.block .pg-title{color:rgba(239,68,68,0.9);}",
            "#phishguard-banner.warn  .pg-title{color:rgba(234,179,8,0.9);}",
            "#phishguard-banner .pg-body{font-size:11px;color:rgba(255,255,255,0.6);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}",
            "#phishguard-banner .pg-domain{font-family:'SF Mono','Consolas',monospace;color:rgba(255,255,255,0.85);}",
            "#phishguard-banner .pg-actions{display:flex;align-items:center;gap:5px;flex-shrink:0;}",
            "#phishguard-banner .pg-btn{",
            "  padding:4px 9px;border-radius:5px;font-size:11px;font-weight:600;",
            "  cursor:pointer;border:1px solid;background:transparent;",
            "  font-family:inherit;white-space:nowrap;transition:background 0.12s;",
            "}",
            "#phishguard-banner.block .pg-btn-leave{color:#ef4444;border-color:rgba(239,68,68,0.4);}",
            "#phishguard-banner.block .pg-btn-leave:hover{background:rgba(239,68,68,0.1);}",
            "#phishguard-banner.warn  .pg-btn-leave{color:#fbbf24;border-color:rgba(234,179,8,0.4);}",
            "#phishguard-banner.warn  .pg-btn-leave:hover{background:rgba(234,179,8,0.1);}",
            "#phishguard-banner .pg-btn-details{color:rgba(255,255,255,0.65);border-color:rgba(255,255,255,0.15);}",
            "#phishguard-banner .pg-btn-details:hover{background:rgba(255,255,255,0.08);}",
            "#phishguard-banner .pg-btn-dismiss{color:rgba(255,255,255,0.4);border-color:transparent;}",
            "#phishguard-banner .pg-btn-dismiss:hover{color:rgba(255,255,255,0.65);}",
            "#phishguard-banner .pg-close{",
            "  width:24px;height:24px;border-radius:4px;border:none;background:transparent;",
            "  cursor:pointer;color:rgba(255,255,255,0.3);display:flex;align-items:center;",
            "  justify-content:center;transition:color 0.12s;flex-shrink:0;",
            "}",
            "#phishguard-banner .pg-close:hover{color:rgba(255,255,255,0.65);}",
            "#phishguard-banner .pg-progress{",
            "  position:absolute;bottom:0;left:0;height:2px;",
            "  background:rgba(234,179,8,0.55);transition:width 1s linear;",
            "}",
        ].join("\n");
        document.head.appendChild(style);
    }

    _build(action, domain) {
        const isBlock = action === "BLOCK";
        const ns      = "http://www.w3.org/2000/svg";

        const banner = document.createElement("div");
        banner.id        = WarningBanner.BANNER_ID;
        banner.className = isBlock ? "block" : "warn";
        // Set initial transform inline so CSS transition can animate it
        banner.style.transform = "translateY(-100%)";

        // ── Icon zone ──────────────────────────────────────
        const iconCircle = document.createElement("div");
        iconCircle.className = "pg-icon-circle";
        iconCircle.appendChild(this._buildIconSvg(isBlock));

        // ── Text zone ──────────────────────────────────────
        const textZone = document.createElement("div");
        textZone.className = "pg-text";

        const title = document.createElement("div");
        title.className   = "pg-title";
        title.textContent = isBlock ? "Phishing Threat Detected" : "Suspicious Site Warning";

        const body = document.createElement("div");
        body.className = "pg-body";
        body.appendChild(document.createTextNode("Flagged domain: "));
        const domainSpan = document.createElement("span");
        domainSpan.className   = "pg-domain";
        domainSpan.textContent = domain;   // textContent — safe, no innerHTML
        body.appendChild(domainSpan);

        textZone.append(title, body);

        // ── Actions zone ───────────────────────────────────
        const actions = document.createElement("div");
        actions.className = "pg-actions";

        const btnLeave = document.createElement("button");
        btnLeave.className   = "pg-btn pg-btn-leave";
        btnLeave.textContent = "Leave this page";
        btnLeave.onclick     = () => chrome.runtime.sendMessage({ type: "LEAVE_SITE" });

        const btnDetails = document.createElement("button");
        btnDetails.className   = "pg-btn pg-btn-details";
        btnDetails.textContent = "View details";
        btnDetails.onclick     = () => chrome.runtime.sendMessage({ type: "OPEN_POPUP" });

        const btnDismiss = document.createElement("button");
        btnDismiss.className   = "pg-btn pg-btn-dismiss";
        btnDismiss.textContent = isBlock ? "Dismiss" : "Ignore warning";
        btnDismiss.onclick     = () => this.dismiss();

        const closeBtn = document.createElement("button");
        closeBtn.className = "pg-close";
        closeBtn.setAttribute("aria-label", "Close");
        closeBtn.onclick = () => this.dismiss();
        closeBtn.appendChild(this._buildCloseSvg());

        actions.append(btnLeave, btnDetails, btnDismiss, closeBtn);
        banner.append(iconCircle, textZone, actions);

        // Countdown progress bar for WARN only
        if (!isBlock) {
            const progress = document.createElement("div");
            progress.className = "pg-progress";
            progress.id        = "phishguard-progress";
            progress.style.width = "100%";
            banner.appendChild(progress);
        }

        return banner;
    }

    _buildIconSvg(isBlock) {
        const ns  = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(ns, "svg");
        svg.setAttribute("viewBox", "0 0 16 16");
        svg.setAttribute("fill", "none");
        svg.setAttribute("width", "16");
        svg.setAttribute("height", "16");
        svg.style.color = isBlock ? "#ef4444" : "#fbbf24";

        if (isBlock) {
            const circle = document.createElementNS(ns, "circle");
            circle.setAttribute("cx", "8"); circle.setAttribute("cy", "8"); circle.setAttribute("r", "6");
            circle.setAttribute("stroke", "currentColor"); circle.setAttribute("stroke-width", "1.5");
            const cross = document.createElementNS(ns, "path");
            cross.setAttribute("d", "M5.5 5.5l5 5M10.5 5.5l-5 5");
            cross.setAttribute("stroke", "currentColor"); cross.setAttribute("stroke-width", "1.5");
            cross.setAttribute("stroke-linecap", "round");
            svg.append(circle, cross);
        } else {
            const tri = document.createElementNS(ns, "path");
            tri.setAttribute("d", "M8 2l6 11H2L8 2z");
            tri.setAttribute("stroke", "currentColor"); tri.setAttribute("stroke-width", "1.5");
            tri.setAttribute("stroke-linejoin", "round");
            const line = document.createElementNS(ns, "path");
            line.setAttribute("d", "M8 7v3.5M8 12.5v.5");
            line.setAttribute("stroke", "currentColor"); line.setAttribute("stroke-width", "1.5");
            line.setAttribute("stroke-linecap", "round");
            svg.append(tri, line);
        }
        return svg;
    }

    _buildCloseSvg() {
        const ns  = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(ns, "svg");
        svg.setAttribute("viewBox", "0 0 12 12");
        svg.setAttribute("fill", "none");
        svg.setAttribute("width", "12");
        svg.setAttribute("height", "12");
        const p = document.createElementNS(ns, "path");
        p.setAttribute("d", "M2 2l8 8M10 2l-8 8");
        p.setAttribute("stroke", "currentColor"); p.setAttribute("stroke-width", "1.5");
        p.setAttribute("stroke-linecap", "round");
        svg.appendChild(p);
        return svg;
    }

    _startCountdown(banner) {
        const DURATION = 8;
        let remaining  = DURATION;
        const bar      = document.getElementById("phishguard-progress");

        this._timer = setInterval(() => {
            remaining--;
            if (bar) bar.style.width = `${(remaining / DURATION) * 100}%`;
            if (remaining <= 0) {
                clearInterval(this._timer);
                this._timer = null;
                this.dismiss();
            }
        }, 1000);
    }
}


// ─────────────────────────────────────────
// PageAnalyser
// ─────────────────────────────────────────

class PageAnalyser {
    constructor(extractor, banner) {
        this._extractor = extractor;
        this._banner    = banner;
        this._debounce  = null;
    }

    run() {
        this._analyse();
        this._watchForDynamicForms();
    }

    _analyse() {
        const features = this._extractor.extract();
        // Save page data immediately so report generation works even before analysis completes
        chrome.storage.local.set({ lastPageData: features });

        chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", data: features }, response => {
            // background.js already saves analysisResult with timestamp — don't overwrite it
            if (!response || window.top !== window.self) return;

            if (response.action === "BLOCK" || response.action === "WARN") {
                this._banner.show(response.action, features.domain || window.location.hostname);
            }
        });
    }

    _watchForDynamicForms() {
        const observer = new MutationObserver(() => {
            if (!document.querySelector("input[type='password']")) return;
            clearTimeout(this._debounce);
            this._debounce = setTimeout(() => {
                this._analyse();
                observer.disconnect();
            }, 700);
        });
        observer.observe(document.body, { childList: true, subtree: true });
    }
}


// ─────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────

if (!window.hasRunPhishGuard) {
    window.hasRunPhishGuard = true;
    new PageAnalyser(new FeatureExtractor(), new WarningBanner()).run();
}
