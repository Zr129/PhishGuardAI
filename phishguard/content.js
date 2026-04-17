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
        const rawUrl     = window.top.location.href;

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
            };
        } catch {
            return {
                has_bank_keywords: false, has_pay_keywords: false, has_crypto_keywords: false,
                has_copyright: false, no_of_images: 0, no_of_css: 0, no_of_js: 0,
            };
        }
    }

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
// Security: uses textContent for all user-controlled strings
// ─────────────────────────────────────────

class WarningBanner {
    static BANNER_ID = "phishguard-alert-banner";
    static HEIGHT    = "80px";

    show(action, message) {
        if (window.top !== window.self) return;
        this._removeExisting();
        const banner = this._buildElement(action, message);
        document.documentElement.prepend(banner);
        document.documentElement.style.marginTop = WarningBanner.HEIGHT;
        document.getElementById("pg-close").onclick = () => this.dismiss();
    }

    dismiss() {
        this._removeExisting();
        document.documentElement.style.marginTop = "0";
    }

    _removeExisting() {
        document.getElementById(WarningBanner.BANNER_ID)?.remove();
    }

    _buildElement(action, message) {
        const isBlock = action === "BLOCK";
        const banner  = document.createElement("div");
        banner.id     = WarningBanner.BANNER_ID;

        Object.assign(banner.style, {
            position: "fixed", top: "0", left: "0", width: "100%",
            height: WarningBanner.HEIGHT, zIndex: "2147483647",
            backgroundColor: isBlock ? "#d93025" : "#f29900",
            color: isBlock ? "#ffffff" : "#000000",
            display: "flex", justifyContent: "center", alignItems: "center",
            fontWeight: "bold", fontSize: "18px",
            fontFamily: "'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
            boxShadow: "0 4px 15px rgba(0,0,0,0.4)", padding: "0 20px",
        });

        // Security: build DOM nodes instead of innerHTML to prevent XSS
        const msgDiv   = document.createElement("div");
        msgDiv.style.cssText = "flex-grow:1; text-align:center;";

        const icon   = document.createTextNode(isBlock ? "🚫 " : "⚠️ ");
        const strong = document.createElement("strong");
        strong.textContent = "PhishGuard: ";
        const text = document.createTextNode(message);   // textContent — safe

        msgDiv.append(icon, strong, text);

        const closeBtn = document.createElement("button");
        closeBtn.id          = "pg-close";
        closeBtn.textContent = "×";
        closeBtn.style.cssText = "margin-left:20px; cursor:pointer; background:none; border:none; font-size:20px; color:inherit;";

        banner.append(msgDiv, closeBtn);
        return banner;
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

        chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", data: features }, response => {
            if (!response || window.top !== window.self) return;

            chrome.storage.local.set({ analysisResult: { url: features.url, data: response } });

            if (response.action === "BLOCK" || response.action === "WARN") {
                const msg = response.action === "BLOCK"
                    ? "Likely phishing activity"
                    : "Suspicious activity detected";
                this._banner.show(response.action, msg);
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
