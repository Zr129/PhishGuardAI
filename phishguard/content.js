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
        const host   = window.location.hostname.replace(/^www\./, "");
        const rawUrl = window.location.href;

        return {
            url:    rawUrl.length > 2048 ? rawUrl.substring(0, 2048) : rawUrl,
            domain: host,
            title:  (document.title || "").substring(0, 200),

            is_https:      window.location.protocol === "https:",
            is_main_frame: window.top === window.self,

            // PhiUSIIL / ML features
            is_responsive:   !!document.querySelector("meta[name='viewport']"),
            has_favicon:     !!document.querySelector("link[rel~='icon']"),
            has_robots:      !!document.querySelector("meta[name='robots']"),
            has_description: !!document.querySelector("meta[name='description']"),
            has_title:       document.title.trim().length > 0,

            // FIX: these were missing — ML model uses DomainTitleMatchScore
            // which maps directly to domain_title_match_score on URLRequest.
            // Without these, the ML feature vector is wrong on every page.
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
                        if (actionHost && actionHost !== host) {
                            actionToDifferentDomain = true;
                        }
                    } catch {
                        actionToDifferentDomain = true;
                    }
                }
            });
        } catch { /* DOM access may fail in sandboxed frames */ }

        // ── Iframe signals (main-page perspective) ───────────────────
        // Complements IFrameTrapCheck which detects being *inside* an iframe.
        // These detect iframes *embedded in* the current page.
        let hasIframe         = false;
        let hasHiddenIframe   = false;
        let hasExternalIframe = false;

        try {
            const iframes = Array.from(document.querySelectorAll("iframe"));
            hasIframe = iframes.length > 0;

            hasHiddenIframe = iframes.some(f => {
                try {
                    const s = window.getComputedStyle(f);
                    return (
                        s.display         === "none"   ||
                        s.visibility      === "hidden" ||
                        parseInt(s.width  || "0") < 5  ||
                        parseInt(s.height || "0") < 5  ||
                        f.getAttribute("hidden") !== null
                    );
                } catch { return false; }
            });

            hasExternalIframe = iframes.some(f => {
                const src = f.getAttribute("src");
                if (!src || src.startsWith("about:") || src.startsWith("javascript:")) return false;
                try {
                    const iframeHost = new URL(src, window.location.href)
                        .hostname.replace(/^www\./, "");
                    return iframeHost && iframeHost !== host;
                } catch { return false; }
            });
        } catch { /* DOM access may fail in sandboxed frames */ }

        return {
            has_password_field:         !!document.querySelector("input[type='password']"),
            is_hidden_submission:       isHiddenSubmission,
            action_to_different_domain: actionToDifferentDomain,
            has_submit_button: !!(
                document.querySelector("input[type='submit']")     ||
                document.querySelector("button[type='submit']")    ||
                document.querySelector("button:not([type])")
            ),
            has_hidden_fields:   !!document.querySelector("input[type='hidden']"),
            has_iframe:          hasIframe,
            has_hidden_iframe:   hasHiddenIframe,
            has_external_iframe: hasExternalIframe,
        };
    }

    _getLinkContext() {
        const host = window.location.hostname.replace(/^www\./, "");
        const SOCIAL = new Set([
            "facebook.com", "twitter.com", "x.com", "instagram.com",
            "linkedin.com", "youtube.com", "tiktok.com", "reddit.com",
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
            const BANK_KW   = ["bank", "credit", "debit", "account", "finance", "loan", "wire transfer"];
            const PAY_KW    = ["payment", "pay now", "checkout", "billing", "invoice", "transaction"];
            const CRYPTO_KW = ["bitcoin", "crypto", "ethereum", "wallet", "blockchain", "nft"];

            return {
                has_bank_keywords:   BANK_KW.some(k   => bodyText.includes(k)),
                has_pay_keywords:    PAY_KW.some(k    => bodyText.includes(k)),
                has_crypto_keywords: CRYPTO_KW.some(k => bodyText.includes(k)),
                has_copyright:       bodyText.includes("©") || bodyText.includes("copyright"),
                no_of_images:        document.querySelectorAll("img").length,
                no_of_css:           document.querySelectorAll("link[rel='stylesheet']").length,
                no_of_js:            document.querySelectorAll("script[src]").length,

                has_auto_download: Array.from(document.querySelectorAll("a[download]"))
                    .some(a => /\.(exe|zip|msi|dmg|pkg|bat|cmd|ps1|vbs|jar)$/i.test(a.href)),

                has_meta_refresh: !!document.querySelector("meta[http-equiv='refresh']"),

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

    // Shared utility: fraction of tokens in `a` that appear in `b`
    _tokenOverlap(a, b) {
        if (!a || !b) return 0;
        const tokenise = s => new Set(
            s.toLowerCase().replace(/[^a-z0-9]/g, " ").split(/\s+/).filter(Boolean)
        );
        const tokA = tokenise(a);
        const tokB = tokenise(b);
        if (!tokA.size || !tokB.size) return 0;
        const shared = [...tokA].filter(t => tokB.has(t)).length;
        return parseFloat((shared / Math.max(tokA.size, tokB.size)).toFixed(3));
    }
}


// ─────────────────────────────────────────
// WarningBanner
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
            // FIX: pass the banner element directly so countdown can find
            // the progress bar even before it's fully in the live DOM
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
        style.textContent = `
#phishguard-banner {
  position:fixed;top:0;left:0;right:0;z-index:2147483647;
  height:56px;display:flex;align-items:center;gap:10px;padding:0 14px;
  transform:translateY(-100%);
  transition:transform 0.28s cubic-bezier(0.4,0,0.2,1);
  font-family:-apple-system,'Segoe UI',system-ui,sans-serif;
}
#phishguard-banner.block{background:#1a0505;border-bottom:1px solid rgba(239,68,68,0.4);}
#phishguard-banner.warn{background:#1c1505;border-bottom:1px solid rgba(234,179,8,0.4);}
#phishguard-banner .pg-text{flex:1;min-width:0;display:flex;flex-direction:column;gap:1px;}
#phishguard-banner .pg-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;}
#phishguard-banner.block .pg-title{color:rgba(239,68,68,0.9);}
#phishguard-banner.warn .pg-title{color:rgba(234,179,8,0.9);}
#phishguard-banner .pg-body{font-size:11px;color:rgba(255,255,255,0.6);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
#phishguard-banner .pg-domain{font-family:'SF Mono','Consolas',monospace;color:rgba(255,255,255,0.85);}
#phishguard-banner .pg-actions{display:flex;align-items:center;gap:5px;flex-shrink:0;}
#phishguard-banner .pg-btn{
  padding:4px 9px;border-radius:5px;font-size:11px;font-weight:600;
  cursor:pointer;border:1px solid;background:transparent;
  font-family:inherit;white-space:nowrap;
}
#phishguard-banner.block .pg-btn-leave{color:#ef4444;border-color:rgba(239,68,68,0.4);}
#phishguard-banner.warn  .pg-btn-leave{color:#fbbf24;border-color:rgba(234,179,8,0.4);}
#phishguard-banner .pg-btn-details{color:rgba(255,255,255,0.65);border-color:rgba(255,255,255,0.15);}
#phishguard-banner .pg-btn-dismiss{color:rgba(255,255,255,0.4);border-color:transparent;}
#phishguard-banner .pg-close{
  width:24px;height:24px;border-radius:4px;border:none;background:transparent;
  cursor:pointer;color:rgba(255,255,255,0.3);
}
#phishguard-banner .pg-progress{
  position:absolute;bottom:0;left:0;height:2px;
  background:rgba(234,179,8,0.55);transition:width 1s linear;
}
        `;
        document.head.appendChild(style);
    }

    _build(action, domain) {
        const isBlock = action === "BLOCK";
        const banner  = document.createElement("div");
        banner.id        = WarningBanner.BANNER_ID;
        banner.className = isBlock ? "block" : "warn";
        banner.style.transform = "translateY(-100%)";

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
        domainSpan.textContent = domain;
        body.appendChild(domainSpan);
        textZone.append(title, body);

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

        actions.append(btnLeave, btnDetails, btnDismiss);
        banner.append(textZone, actions);

        if (!isBlock) {
            const progress = document.createElement("div");
            progress.className = "pg-progress";
            progress.id        = "phishguard-progress";
            progress.style.width = "100%";
            banner.appendChild(progress);
        }

        return banner;
    }

    // FIX: accept banner element directly — avoids getElementById timing issue
    // when progress bar hasn't been inserted into the live DOM yet
    _startCountdown(banner) {
        const DURATION = 8;
        let remaining  = DURATION;
        const bar      = banner.querySelector("#phishguard-progress");

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

        // Guard: only analyse main frames.
        // content.js entry point already restricts to window.top === window.self
        // but this is a safety net in case of edge cases.
        if (!features.is_main_frame) return;

        chrome.storage.local.set({ lastPageData: features });

        chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", data: features }, response => {
            if (!response || window.top !== window.self) return;
            if (response.action === "BLOCK" || response.action === "WARN") {
                this._banner.show(response.action, features.domain || window.location.hostname);
            }
        });
    }

    _watchForDynamicForms() {
        if (!document.body) return;

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
// Guard: only run in the main frame (window === window.top).
// This prevents iframes from sending their own ANALYZE_PAGE messages
// and overwriting the main page result in chrome.storage.
// ─────────────────────────────────────────

if (!window.hasRunPhishGuard && window === window.top) {
    window.hasRunPhishGuard = true;

    const start = () => {
        if (!document.body) return;

        // FIX: removed the 200-char body text threshold.
        // Many phishing pages are minimal login forms with very little
        // body text — that threshold was silently skipping real threats.
        // The analysis cost is negligible so there is no benefit to skipping.

        new PageAnalyser(
            new FeatureExtractor(),
            new WarningBanner()
        ).run();
    };

    if (document.readyState === "loading") {
        window.addEventListener("DOMContentLoaded", start);
    } else {
        start();
    }
}
