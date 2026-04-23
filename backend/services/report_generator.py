"""
ReportGenerator — JSON-first LLM report rendered to PDF via WeasyPrint.

Pipeline:
  1. WHOIS lookup via DomainIntelligence
  2. Build structured context string from all page data + detection flags
  3. One-shot LLM prompt (llama-3.3-70b-versatile) → rich JSON analysis
  4. Jinja2 renders JSON into a self-contained, print-optimised HTML template
  5. WeasyPrint converts HTML → PDF bytes
  6. Returns pdf_bytes (raises if WeasyPrint not installed)

LLM JSON schema:
  {
    risk_rating:         "CRITICAL|HIGH|MODERATE|LOW|SAFE"
    executive_summary:   paragraph — plain English overview for any user
    threat_assessment:   paragraph — what the threat is and how it works
    url_analysis:        paragraph — URL/domain specific findings
    whois_analysis:      paragraph — domain age, registrar, red flags
    behaviour_analysis:  paragraph — page behaviour findings
    technical_indicators: ["bullet 1", "bullet 2", ...]  — specific technical findings
    recommendations:     ["action 1", "action 2", ...]   — what the user should do
    confidence_notes:    sentence — caveat on detection confidence
  }
"""

import json
import logging
import os
from datetime import datetime, timezone

from models.models import URLRequest, AnalysisResult
from utils.whois_lookup import DomainIntelligence

logger = logging.getLogger("PhishGuard")

MODEL = "llama-3.3-70b-versatile"


def _get_groq_api_key() -> str:
    return os.getenv("GROQ_API_KEY", "").strip()

# Header background and risk accent colours per risk rating
_RISK_COLOURS = {
    "CRITICAL": ("#7f1d1d", "#dc2626"),
    "HIGH":     ("#78350f", "#d97706"),
    "MODERATE": ("#78350f", "#d97706"),
    "LOW":      ("#14532d", "#16a34a"),
    "SAFE":     ("#14532d", "#16a34a"),
}

# ── LLM System Prompt ─────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a senior cybersecurity analyst writing a structured threat report for a
phishing detection system. Your audience includes both technical and non-technical users.

Respond ONLY with a valid JSON object. No markdown, no prose outside the JSON, no code fences.

JSON schema (all fields required):
{
  "risk_rating": "CRITICAL|HIGH|MODERATE|LOW|SAFE",

  "executive_summary": "3-4 sentence plain-English overview. State the verdict clearly,
    explain what was found, and what the user should do. Avoid jargon.",

  "threat_assessment": "2-3 sentences. Describe what type of threat this appears to be
    (e.g. credential harvesting, brand impersonation, drive-by download) and how it works.
    If SAFE, explain why the site appears legitimate.",

  "url_analysis": "2-3 sentences. Analyse the URL structure and domain specifically.
    Comment on domain age, subdomain depth, URL length, obfuscation, and any red flags.
    Be specific — reference the actual domain name.",

  "whois_analysis": "2-3 sentences. Interpret the WHOIS data. Comment on domain age
    (flag anything under 90 days as high risk), registrar, country, and name servers.
    Note if data is hidden or unavailable — this itself is a red flag.",

  "behaviour_analysis": "2-3 sentences. Interpret the page behaviour signals.
    Comment on form submission patterns, password field usage, script behaviour,
    redirect patterns, and download triggers found on the page.",

  "technical_indicators": [
    "Specific technical finding 1 — be precise, e.g. 'Form submits credentials to external domain evil.com'",
    "Specific technical finding 2",
    "Specific technical finding 3 (add more if warranted, minimum 2)"
  ],

  "recommendations": [
    "Specific action 1 — e.g. 'Do not enter any credentials on this page'",
    "Specific action 2 — e.g. 'Report this URL to your IT security team'",
    "Specific action 3 — e.g. 'Run a malware scan if you have already interacted with this page'",
    "Specific action 4 (add more if appropriate)"
  ],

  "confidence_notes": "1 sentence. Note any factors that may affect detection confidence,
    such as a newly registered domain with limited data, or that the site may be a
    false positive if it is a known legitimate service."
}

Rules:
- Base risk_rating strictly on the evidence provided.
- CRITICAL = confirmed phishing indicators (blacklisted, brand impersonation with password, IP URL).
- HIGH = strong phishing signals (new domain + password field, cross-domain form submission).
- MODERATE = suspicious signals present but not conclusive.
- LOW = minor signals, likely legitimate.
- SAFE = no phishing indicators detected.
- New domains under 90 days old are at minimum HIGH risk.
- Be decisive and specific. Never use vague phrases like "may potentially possibly suggest".
- Reference actual values from the data (domain name, specific flags, age in days).
"""

# ── Jinja2 HTML Template (PDF-optimised) ─────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PhishGuard Security Report — {{ domain }}</title>
<style>
  /* ── Reset & base ── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.55;
    color: #1a1a1a;
    background: #fff;
  }

  /* ── Page layout (PDF) ── */
  @page {
    size: A4;
    margin: 15mm 18mm 18mm 18mm;
    @bottom-right {
      content: "Page " counter(page) " of " counter(pages);
      font-size: 8pt;
      color: #9ca3af;
    }
  }

  .page-break { page-break-before: always; }

  /* ── Header band ── */
  .header {
    background: {{ header_colour }};
    color: #fff;
    padding: 20px 24px 18px;
    margin-bottom: 0;
  }
  .header-top {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 10px;
  }
  .brand-line {
    font-size: 9pt;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    opacity: 0.75;
  }
  .verdict-pill {
    background: rgba(255,255,255,0.18);
    border: 1px solid rgba(255,255,255,0.35);
    border-radius: 4px;
    padding: 3px 10px;
    font-size: 9pt;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .header-domain {
    font-size: 20pt;
    font-weight: 700;
    word-break: break-all;
    line-height: 1.2;
    margin-bottom: 4px;
  }
  .header-meta {
    font-size: 8.5pt;
    opacity: 0.65;
  }

  /* ── Risk meter ── */
  .risk-band {
    background: #f9fafb;
    border-bottom: 1px solid #e5e7eb;
    padding: 14px 24px;
    display: flex;
    align-items: center;
    gap: 20px;
  }
  .risk-label-group { flex: 1; }
  .risk-label-top {
    font-size: 8pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: #6b7280;
    margin-bottom: 4px;
  }
  .risk-value {
    font-size: 18pt;
    font-weight: 800;
    color: {{ risk_colour }};
    line-height: 1;
  }
  .risk-bar-wrap { flex: 2; }
  .risk-bar-track {
    height: 7px;
    background: #e5e7eb;
    border-radius: 4px;
    overflow: hidden;
  }
  .risk-bar-fill {
    height: 100%;
    background: {{ risk_colour }};
    border-radius: 4px;
    width: {{ confidence }}%;
  }
  .risk-pct {
    font-size: 13pt;
    font-weight: 700;
    color: {{ risk_colour }};
    white-space: nowrap;
  }

  /* ── Sections ── */
  .section {
    padding: 16px 24px;
    border-bottom: 1px solid #e5e7eb;
  }
  .section:last-child { border-bottom: none; }
  .section-title {
    font-size: 8pt;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: #6b7280;
    margin-bottom: 8px;
    padding-bottom: 5px;
    border-bottom: 1px solid #f3f4f6;
  }
  .prose {
    font-size: 10.5pt;
    line-height: 1.65;
    color: #374151;
  }

  /* ── Data grid ── */
  .data-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 6px 16px;
    margin-top: 10px;
  }
  .data-row { display: flex; flex-direction: column; gap: 1px; }
  .data-key {
    font-size: 7.5pt;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #9ca3af;
    font-weight: 600;
  }
  .data-val {
    font-size: 10pt;
    color: #111827;
    font-weight: 500;
    word-break: break-all;
  }
  .data-val.warn { color: #d97706; font-weight: 700; }
  .data-val.danger { color: #dc2626; font-weight: 700; }

  /* ── Detection flags ── */
  .flags-list { display: flex; flex-direction: column; gap: 5px; margin-top: 2px; }
  .flag {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    border-radius: 4px;
    border-left: 2.5px solid;
    page-break-inside: avoid;
  }
  .flag.rule      { background: #fef2f2; border-color: #dc2626; }
  .flag.heuristic { background: #fffbeb; border-color: #d97706; }
  .flag.ml        { background: #eff6ff; border-color: #3b82f6; }
  .flag-badge {
    font-size: 7pt;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 2px 5px;
    border-radius: 3px;
    color: #fff;
    flex-shrink: 0;
  }
  .flag.rule .flag-badge      { background: #dc2626; }
  .flag.heuristic .flag-badge { background: #d97706; }
  .flag.ml .flag-badge        { background: #3b82f6; }
  .flag-text { font-size: 10pt; color: #374151; }

  /* ── Bullet lists (technical indicators) ── */
  .bullet-list { margin: 4px 0 0 0; padding-left: 18px; }
  .bullet-list li {
    font-size: 10.5pt;
    color: #374151;
    line-height: 1.6;
    margin-bottom: 4px;
    page-break-inside: avoid;
  }

  /* ── Recommendations ── */
  .recs-list { display: flex; flex-direction: column; gap: 8px; margin-top: 2px; }
  .rec {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    page-break-inside: avoid;
  }
  .rec-num {
    min-width: 20px;
    height: 20px;
    background: {{ risk_colour }};
    color: #fff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 9pt;
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 1px;
  }
  .rec-text { font-size: 10.5pt; color: #374151; line-height: 1.6; }

  /* ── Confidence note ── */
  .confidence-note {
    background: #f3f4f6;
    border-radius: 4px;
    padding: 10px 14px;
    font-size: 9.5pt;
    color: #6b7280;
    font-style: italic;
    margin-top: 8px;
  }

  /* ── Footer ── */
  .report-footer {
    padding: 12px 24px;
    background: #f9fafb;
    border-top: 1px solid #e5e7eb;
    display: flex;
    justify-content: space-between;
    font-size: 8.5pt;
    color: #9ca3af;
  }
</style>
</head>
<body>

  <!-- ── Header ── -->
  <div class="header">
    <div class="header-top">
      <span class="brand-line">PhishGuard &mdash; Security Report</span>
      <span class="verdict-pill">{{ result_action }}</span>
    </div>
    <div class="header-domain">{{ domain }}</div>
    <div class="header-meta">Analysed {{ timestamp }} &nbsp;&bull;&nbsp; Confidence {{ confidence }}%</div>
  </div>

  <!-- ── Risk meter ── -->
  <div class="risk-band">
    <div class="risk-label-group">
      <div class="risk-label-top">Risk Rating</div>
      <div class="risk-value">{{ risk_rating }}</div>
    </div>
    <div class="risk-bar-wrap">
      <div class="risk-bar-track"><div class="risk-bar-fill"></div></div>
    </div>
    <div class="risk-pct">{{ confidence }}%</div>
  </div>

  <!-- ── Executive Summary ── -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <p class="prose">{{ executive_summary }}</p>
  </div>

  <!-- ── Threat Assessment ── -->
  <div class="section">
    <div class="section-title">Threat Assessment</div>
    <p class="prose">{{ threat_assessment }}</p>
  </div>

  <!-- ── Detection Flags ── -->
  {% if tagged_flags %}
  <div class="section">
    <div class="section-title">Detection Flags ({{ tagged_flags | length }})</div>
    <div class="flags-list">
      {% for flag in tagged_flags %}
      <div class="flag {{ flag.tier_cls }}">
        <span class="flag-badge">{{ flag.tier_label }}</span>
        <span class="flag-text">{{ flag.text }}</span>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- ── Technical Indicators (LLM) ── -->
  {% if technical_indicators %}
  <div class="section">
    <div class="section-title">Technical Indicators</div>
    <ul class="bullet-list">
      {% for indicator in technical_indicators %}
      <li>{{ indicator }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  <!-- ── URL Analysis ── -->
  <div class="section">
    <div class="section-title">URL &amp; Domain Analysis</div>
    <p class="prose">{{ url_analysis }}</p>
    <div class="data-grid">
      <div class="data-row">
        <span class="data-key">URL</span>
        <span class="data-val">{{ url_short }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Domain</span>
        <span class="data-val">{{ domain }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Protocol</span>
        <span class="data-val {{ 'danger' if not is_https else '' }}">
          {{ "HTTPS" if is_https else "HTTP (Insecure)" }}
        </span>
      </div>
      <div class="data-row">
        <span class="data-key">Subdomains</span>
        <span class="data-val {{ 'warn' if subdomain_count > 2 else '' }}">{{ subdomain_count }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">URL Length</span>
        <span class="data-val {{ 'warn' if url_length > 100 else '' }}">{{ url_length }} chars</span>
      </div>
      <div class="data-row">
        <span class="data-key">Raw IP</span>
        <span class="data-val {{ 'danger' if is_ip else '' }}">{{ "Yes (suspicious)" if is_ip else "No" }}</span>
      </div>
    </div>
  </div>

  <!-- ── WHOIS ── -->
  <div class="section">
    <div class="section-title">WHOIS &amp; Domain Intelligence</div>
    <p class="prose">{{ whois_analysis }}</p>
    <div class="data-grid">
      <div class="data-row">
        <span class="data-key">Registrar</span>
        <span class="data-val">{{ whois_registrar }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Country</span>
        <span class="data-val">{{ whois_country }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Created</span>
        <span class="data-val">{{ whois_created }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Expires</span>
        <span class="data-val">{{ whois_expires }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Domain Age</span>
        <span class="data-val {{ 'danger' if whois_age_days and whois_age_days < 90 else '' }}">
          {{ whois_age }}
        </span>
      </div>
      <div class="data-row">
        <span class="data-key">Name Servers</span>
        <span class="data-val">{{ whois_ns }}</span>
      </div>
    </div>
  </div>

  <!-- ── Page Behaviour ── -->
  <div class="section">
    <div class="section-title">Page Behaviour</div>
    <p class="prose">{{ behaviour_analysis }}</p>
    <div class="data-grid">
      <div class="data-row">
        <span class="data-key">Password Field</span>
        <span class="data-val {{ 'warn' if has_password else '' }}">{{ "Yes" if has_password else "No" }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Hidden Form</span>
        <span class="data-val {{ 'warn' if is_hidden_submission else '' }}">{{ "Yes" if is_hidden_submission else "No" }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">External Form</span>
        <span class="data-val {{ 'danger' if action_to_different_domain else '' }}">{{ "Yes" if action_to_different_domain else "No" }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Social Links</span>
        <span class="data-val">{{ "Yes" if has_social_net else "No" }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Copyright</span>
        <span class="data-val">{{ "Yes" if has_copyright else "No" }}</span>
      </div>
      <div class="data-row">
        <span class="data-key">Images / Scripts</span>
        <span class="data-val">{{ no_of_images }} / {{ no_of_js }}</span>
      </div>
    </div>
  </div>

  <!-- ── Recommendations ── -->
  <div class="section">
    <div class="section-title">Recommendations</div>
    <div class="recs-list">
      {% for num, rec in recommendations %}
      <div class="rec">
        <span class="rec-num">{{ num }}</span>
        <span class="rec-text">{{ rec }}</span>
      </div>
      {% endfor %}
    </div>
  </div>

  <!-- ── Confidence Notes ── -->
  {% if confidence_notes %}
  <div class="section">
    <div class="section-title">Confidence Notes</div>
    <div class="confidence-note">{{ confidence_notes }}</div>
  </div>
  {% endif %}

  <!-- ── Footer ── -->
  <div class="report-footer">
    <span>Generated by PhishGuard &mdash; Real-time Phishing Detection</span>
    <span>{{ timestamp }}</span>
  </div>

</body>
</html>"""


# ── Fallback analysis if LLM JSON fails ──────────────────────────────

_FALLBACK_ANALYSIS = {
    "risk_rating":        "MODERATE",
    "executive_summary":  "Analysis could not be fully completed. The detection flags below were identified by the automated pipeline. Please review them carefully before proceeding.",
    "threat_assessment":  "Automated threat assessment is unavailable. Review the detection flags for specific indicators.",
    "url_analysis":       "URL data was collected but structured LLM analysis is unavailable.",
    "whois_analysis":     "WHOIS data was collected but structured LLM analysis is unavailable.",
    "behaviour_analysis": "Page behaviour was logged but structured LLM analysis is unavailable.",
    "technical_indicators": [
        "Automated analysis pipeline completed — see detection flags for specific findings.",
    ],
    "recommendations": [
        "Do not enter credentials on this page.",
        "Verify the domain name carefully before proceeding.",
        "Contact the website owner through a trusted channel to confirm legitimacy.",
        "If in doubt, close the page and navigate directly to the official website.",
    ],
    "confidence_notes": "LLM analysis was unavailable — confidence assessment is based on automated rule and heuristic checks only.",
}


# ── Context builder ───────────────────────────────────────────────────

def _build_context(data: URLRequest, result: AnalysisResult, refined: dict, whois: dict) -> str:
    """Build the context string sent to the LLM."""
    flags = "\n".join(
        f"  - [{r.get('tier', '?')}] {r.get('text', '')}"
        for r in result.tagged_reasons
    ) or "  None detected"

    age = f"{whois['age_days']} days old" if whois.get("age_days") else "Unknown"
    if whois.get("age_days") and whois["age_days"] < 90:
        age += " ⚠ VERY NEW DOMAIN — HIGH RISK"

    ns = ", ".join(whois.get("name_servers", [])[:3]) or "Unknown"

    return (
        f"VERDICT: {result.action} | {result.prediction.upper()} | Confidence {result.confidence}%\n"
        f"\n"
        f"=== URL DETAILS ===\n"
        f"URL: {data.url}\n"
        f"Domain: {refined.get('registered_domain', data.domain)}\n"
        f"Title: {data.title or 'None'}\n"
        f"Protocol: {'HTTPS (secure)' if data.is_https else 'HTTP — INSECURE'}\n"
        f"Raw IP address: {'Yes — SUSPICIOUS' if refined.get('is_ip') else 'No'}\n"
        f"Subdomain count: {refined.get('subdomain_count', 0)}\n"
        f"URL length: {len(data.url)} chars\n"
        f"\n"
        f"=== WHOIS DATA ===\n"
        f"Registrar: {whois.get('registrar') or 'Unknown / Hidden'}\n"
        f"Country: {whois.get('country') or 'Unknown'}\n"
        f"Created: {whois.get('created') or 'Unknown'}\n"
        f"Expires: {whois.get('expires') or 'Unknown'}\n"
        f"Age: {age}\n"
        f"Name servers: {ns}\n"
        f"\n"
        f"=== PAGE BEHAVIOUR ===\n"
        f"Password field present: {'Yes' if data.has_password_field else 'No'}\n"
        f"Hidden form submission: {'Yes — SUSPICIOUS' if data.is_hidden_submission else 'No'}\n"
        f"Form posts to external domain: {'Yes — SUSPICIOUS' if data.action_to_different_domain else 'No'}\n"
        f"Auto-download triggered: {'Yes — SUSPICIOUS' if getattr(data, 'has_auto_download', False) else 'No'}\n"
        f"Meta refresh redirect: {'Yes — SUSPICIOUS' if getattr(data, 'has_meta_refresh', False) else 'No'}\n"
        f"Social media links: {'Yes' if data.has_social_net else 'No'}\n"
        f"Copyright present: {'Yes' if data.has_copyright else 'No'}\n"
        f"Images: {data.no_of_images or 0}  |  Scripts: {data.no_of_js or 0}  |  Stylesheets: {data.no_of_css or 0}\n"
        f"Bank keywords: {'Yes' if data.has_bank_keywords else 'No'}\n"
        f"Payment keywords: {'Yes' if data.has_pay_keywords else 'No'}\n"
        f"\n"
        f"=== DETECTION FLAGS ===\n"
        f"{flags}\n"
    )


# ── ReportGenerator ───────────────────────────────────────────────────

class ReportGenerator:

    def __init__(self, domain_intel: DomainIntelligence = None):
        self._whois = domain_intel or DomainIntelligence()

    def generate(
        self,
        data:    URLRequest,
        result:  AnalysisResult,
        refined: dict,
    ) -> bytes:
        """
        Returns PDF bytes.
        Raises ValueError if GROQ_API_KEY not set.
        Raises RuntimeError if WeasyPrint is not installed.
        """
        groq_api_key = _get_groq_api_key()
        if not groq_api_key:
            raise ValueError(
                "GROQ_API_KEY not set in environment. "
                "Add it to backend/.env to enable report generation."
            )

        domain = refined.get("registered_domain", data.domain)
        logger.info(f"[REPORT] Starting report for {domain}")

        # Step 1 — WHOIS
        logger.info(f"[REPORT] WHOIS lookup for {domain}")
        whois = self._whois.lookup(domain)
        logger.info(f"[REPORT] WHOIS: age={whois.get('age_days')} days, registrar={whois.get('registrar')}")

        # Step 2 — Build LLM context
        context = _build_context(data, result, refined, whois)
        logger.info(f"[REPORT] Calling LLM — context length {len(context)} chars")

        # Step 3 — LLM analysis
        analysis = self._call_llm(context, groq_api_key)
        logger.info(f"[REPORT] LLM risk_rating={analysis.get('risk_rating')}")

        # Step 4 — Render HTML
        html = self._render_html(data, result, refined, whois, analysis)

        # Step 5 — Convert to PDF (required — no HTML fallback)
        pdf_bytes = self._render_pdf(html)
        logger.info(f"[REPORT] PDF generated — {len(pdf_bytes):,} bytes")

        return pdf_bytes

    def _call_llm(self, context: str, groq_api_key: str) -> dict:
        from langchain_groq import ChatGroq
        from langchain_core.messages import SystemMessage, HumanMessage

        llm = ChatGroq(
            model=MODEL,
            api_key=groq_api_key,
            temperature=0.15,   # Lower temp = more consistent, factual output
            max_tokens=2048,    # More tokens for richer analysis
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Analyse this security scan data:\n\n{context}"),
        ]

        response = llm.invoke(messages)
        raw = response.content.strip()

        # Strip markdown code fences if model wraps response
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1].strip()
            if raw.endswith("```"):
                raw = raw.rsplit("```", 1)[0].strip()

        try:
            parsed = json.loads(raw)
            logger.info(f"[REPORT] LLM JSON parsed OK — keys: {list(parsed.keys())}")
            return parsed
        except Exception as e:
            logger.warning(f"[REPORT] LLM JSON parse failed ({e}) — using fallback analysis")
            return _FALLBACK_ANALYSIS.copy()

    def _render_html(
        self,
        data:     URLRequest,
        result:   AnalysisResult,
        refined:  dict,
        whois:    dict,
        analysis: dict,
    ) -> str:
        from jinja2 import Template

        risk_rating   = str(analysis.get("risk_rating", "MODERATE")).upper()
        header_colour, risk_colour = _RISK_COLOURS.get(risk_rating, _RISK_COLOURS["MODERATE"])

        _tier_map = {
            "RULE":      ("rule",      "Rule"),
            "HEURISTIC": ("heuristic", "Heuristic"),
            "ML":        ("ml",        "ML"),
        }
        tagged_flags = []
        for r in result.tagged_reasons:
            tier     = str(r.get("tier") or "RULE").upper()
            cls, lbl = _tier_map.get(tier, ("rule", "Rule"))
            tagged_flags.append({
                "text":       r.get("text", ""),
                "tier_cls":   cls,
                "tier_label": lbl,
            })

        age_days  = whois.get("age_days")
        whois_age = f"{age_days} days" if age_days else "Unknown"
        if age_days and age_days < 90:
            whois_age += " (very new — high risk)"

        domain    = refined.get("registered_domain", data.domain)
        url       = data.url
        url_short = url[:90] + "…" if len(url) > 90 else url
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        technical_indicators = analysis.get("technical_indicators", [])
        recs_raw             = analysis.get("recommendations", [])
        recommendations      = list(enumerate(recs_raw, 1))

        ctx = {
            "domain":              domain,
            "url_short":           url_short,
            "timestamp":           timestamp,
            "result_action":       result.action,
            "risk_rating":         risk_rating,
            "header_colour":       header_colour,
            "risk_colour":         risk_colour,
            "confidence":          result.confidence,
            # LLM sections
            "executive_summary":   analysis.get("executive_summary", ""),
            "threat_assessment":   analysis.get("threat_assessment", ""),
            "url_analysis":        analysis.get("url_analysis", ""),
            "whois_analysis":      analysis.get("whois_analysis", ""),
            "behaviour_analysis":  analysis.get("behaviour_analysis", ""),
            "technical_indicators": technical_indicators,
            "recommendations":     recommendations,
            "confidence_notes":    analysis.get("confidence_notes", ""),
            # Data
            "tagged_flags":        tagged_flags,
            "is_https":            data.is_https,
            "subdomain_count":     refined.get("subdomain_count", 0),
            "url_length":          len(data.url),
            "is_ip":               refined.get("is_ip", False),
            "whois_registrar":     whois.get("registrar") or "Unknown",
            "whois_country":       whois.get("country") or "Unknown",
            "whois_created":       whois.get("created") or "Unknown",
            "whois_expires":       whois.get("expires") or "Unknown",
            "whois_age":           whois_age,
            "whois_age_days":      age_days,
            "whois_ns":            ", ".join((whois.get("name_servers") or [])[:2]) or "Unknown",
            "has_password":        data.has_password_field,
            "is_hidden_submission":       data.is_hidden_submission,
            "action_to_different_domain": data.action_to_different_domain,
            "has_social_net":      data.has_social_net,
            "has_copyright":       data.has_copyright,
            "no_of_images":        data.no_of_images or 0,
            "no_of_js":            data.no_of_js or 0,
        }

        return Template(_HTML_TEMPLATE).render(**ctx)

    @staticmethod
    def _render_pdf(html: str) -> bytes:
        """
        Convert HTML to PDF using pdfkit + wkhtmltopdf.
        """
        import pdfkit

        try:
            config = pdfkit.configuration(
                wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
            )
        except Exception as e:
            raise RuntimeError(
                "wkhtmltopdf not found. Ensure it is installed at "
                r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
            ) from e

        try:
            pdf_bytes = pdfkit.from_string(html, False, configuration=config)
            return pdf_bytes
        except Exception as e:
            logger.error(f"[REPORT] PDF render error (pdfkit): {e}")
            raise RuntimeError(f"PDF generation failed: {e}") from e