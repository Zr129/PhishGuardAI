"""
ReportGenerator — JSON-first LLM report with Jinja2 + optional WeasyPrint PDF.

Pipeline:
  1. WHOIS lookup via DomainIntelligence
  2. Build structured context string from all page data
  3. One-shot LLM prompt (llama-3.3-70b-versatile) → JSON only:
     {risk_rating, summary, url_analysis, whois_analysis, behaviour_analysis, recommendations[]}
  4. Jinja2 renders JSON into self-contained HTML template
  5. WeasyPrint converts to PDF (falls back to HTML if not installed)
  6. Returns (pdf_bytes | None, html_string)
"""

import json
import logging
import os
from datetime import datetime

from models.models import URLRequest, AnalysisResult
from utils.whois_lookup import DomainIntelligence

logger = logging.getLogger("PhishGuard")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
MODEL        = "llama-3.3-70b-versatile"

# (header_bg, risk_colour) per risk rating
_RISK_COLOURS = {
    "CRITICAL": ("#991b1b", "#dc2626"),
    "HIGH":     ("#92400e", "#d97706"),
    "MODERATE": ("#92400e", "#d97706"),
    "LOW":      ("#065f46", "#059669"),
    "SAFE":     ("#065f46", "#059669"),
}

SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst. "
    "Respond ONLY with a valid JSON object — no markdown, no prose, no code fences.\n\n"
    "Schema:\n"
    "{\n"
    '  "risk_rating":        "CRITICAL|HIGH|MODERATE|LOW|SAFE",\n'
    '  "summary":            "2-3 sentence executive summary",\n'
    '  "url_analysis":       "1-2 sentence URL and domain assessment",\n'
    '  "whois_analysis":     "1-2 sentence WHOIS and domain age assessment",\n'
    '  "behaviour_analysis": "1-2 sentence page behaviour assessment",\n'
    '  "recommendations":    ["action 1", "action 2", "action 3"]\n'
    "}\n\n"
    "Base risk_rating on the provided evidence. "
    "New domains (<90 days) are at minimum HIGH risk. Be decisive."
)

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PhishGuard Security Report &mdash; {{ domain }}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, 'Segoe UI', system-ui, sans-serif; background: #f8f9fb; color: #0f1117; font-size: 14px; line-height: 1.6; }
  .container { max-width: 740px; margin: 0 auto; background: #fff; box-shadow: 0 2px 16px rgba(0,0,0,0.08); }

  .header { background: {{ header_colour }}; color: #fff; padding: 28px 32px; }
  .header-top { display: flex; justify-content: space-between; align-items: flex-start; }
  .brand { font-size: 12px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; opacity: 0.7; }
  .verdict-badge { display: inline-block; background: rgba(255,255,255,0.15); border: 1px solid rgba(255,255,255,0.3); border-radius: 6px; padding: 4px 12px; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.8px; }
  .domain-title { font-size: 22px; font-weight: 700; margin-top: 12px; word-break: break-all; }
  .subtitle { font-size: 12px; opacity: 0.65; margin-top: 4px; }

  .risk-meter { padding: 20px 32px; border-bottom: 1px solid #e5e7eb; }
  .risk-label { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.4px; }
  .risk-value { color: {{ risk_colour }}; font-size: 16px; font-weight: 800; }
  .progress-track { height: 8px; background: #e5e7eb; border-radius: 4px; overflow: hidden; }
  .progress-fill { height: 100%; background: {{ risk_colour }}; border-radius: 4px; width: {{ confidence }}%; }

  .section { padding: 20px 32px; border-bottom: 1px solid #e5e7eb; }
  .section-title { font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.7px; color: #6b7280; margin-bottom: 12px; }
  .prose { font-size: 14px; line-height: 1.7; color: #374151; }

  .data-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 20px; margin-top: 12px; }
  .data-row { display: flex; flex-direction: column; gap: 2px; }
  .data-key { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #9ca3af; font-weight: 600; }
  .data-val { font-size: 13px; color: #111827; font-weight: 500; }

  .flags-list { display: flex; flex-direction: column; gap: 6px; }
  .flag { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-radius: 6px; border-left: 2px solid; }
  .flag.rule      { background: #fef2f2; border-color: #dc2626; }
  .flag.heuristic { background: #fffbeb; border-color: #d97706; }
  .flag.ml        { background: #eff6ff; border-color: #3b82f6; }
  .flag-badge { font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; padding: 2px 5px; border-radius: 3px; color: #fff; flex-shrink: 0; }
  .flag.rule .flag-badge      { background: #dc2626; }
  .flag.heuristic .flag-badge { background: #d97706; }
  .flag.ml .flag-badge        { background: #3b82f6; }
  .flag-text { font-size: 13px; color: #374151; }

  .recs-list { display: flex; flex-direction: column; gap: 10px; }
  .rec { display: flex; gap: 12px; align-items: flex-start; }
  .rec-num { width: 22px; height: 22px; background: {{ risk_colour }}; color: #fff; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; flex-shrink: 0; margin-top: 2px; }
  .rec-text { font-size: 13px; color: #374151; line-height: 1.6; }

  .footer { padding: 16px 32px; background: #f9fafb; border-top: 1px solid #e5e7eb; display: flex; justify-content: space-between; font-size: 11px; color: #9ca3af; }
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div class="header-top">
      <span class="brand">PhishGuard Security Report</span>
      <span class="verdict-badge">{{ result_action }}</span>
    </div>
    <div class="domain-title">{{ domain }}</div>
    <div class="subtitle">Analysed {{ timestamp }}</div>
  </div>

  <div class="risk-meter">
    <div class="risk-label">
      <span>Risk Level</span>
      <span class="risk-value">{{ risk_rating }}</span>
    </div>
    <div class="progress-track"><div class="progress-fill"></div></div>
  </div>

  <div class="section">
    <div class="section-title">Executive Summary</div>
    <p class="prose">{{ summary }}</p>
  </div>

  {% if tagged_flags %}
  <div class="section">
    <div class="section-title">Detection Flags</div>
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

  <div class="section">
    <div class="section-title">URL Analysis</div>
    <p class="prose">{{ url_analysis }}</p>
    <div class="data-grid">
      <div class="data-row"><span class="data-key">URL</span><span class="data-val">{{ url_short }}</span></div>
      <div class="data-row"><span class="data-key">Domain</span><span class="data-val">{{ domain }}</span></div>
      <div class="data-row"><span class="data-key">Protocol</span><span class="data-val">{{ "HTTPS" if is_https else "HTTP (Insecure)" }}</span></div>
      <div class="data-row"><span class="data-key">Subdomains</span><span class="data-val">{{ subdomain_count }}</span></div>
      <div class="data-row"><span class="data-key">URL Length</span><span class="data-val">{{ url_length }} chars</span></div>
      <div class="data-row"><span class="data-key">Raw IP</span><span class="data-val">{{ "Yes" if is_ip else "No" }}</span></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">WHOIS / Domain Intelligence</div>
    <p class="prose">{{ whois_analysis }}</p>
    <div class="data-grid">
      <div class="data-row"><span class="data-key">Registrar</span><span class="data-val">{{ whois_registrar }}</span></div>
      <div class="data-row"><span class="data-key">Country</span><span class="data-val">{{ whois_country }}</span></div>
      <div class="data-row"><span class="data-key">Created</span><span class="data-val">{{ whois_created }}</span></div>
      <div class="data-row"><span class="data-key">Expires</span><span class="data-val">{{ whois_expires }}</span></div>
      <div class="data-row"><span class="data-key">Domain Age</span><span class="data-val">{{ whois_age }}</span></div>
      <div class="data-row"><span class="data-key">Name Servers</span><span class="data-val">{{ whois_ns }}</span></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Page Behaviour</div>
    <p class="prose">{{ behaviour_analysis }}</p>
    <div class="data-grid">
      <div class="data-row"><span class="data-key">Password Field</span><span class="data-val">{{ "Yes" if has_password else "No" }}</span></div>
      <div class="data-row"><span class="data-key">Hidden Form</span><span class="data-val">{{ "Yes" if is_hidden_submission else "No" }}</span></div>
      <div class="data-row"><span class="data-key">External Form</span><span class="data-val">{{ "Yes" if action_to_different_domain else "No" }}</span></div>
      <div class="data-row"><span class="data-key">Social Links</span><span class="data-val">{{ "Yes" if has_social_net else "No" }}</span></div>
      <div class="data-row"><span class="data-key">Copyright</span><span class="data-val">{{ "Yes" if has_copyright else "No" }}</span></div>
      <div class="data-row"><span class="data-key">Images / Scripts</span><span class="data-val">{{ no_of_images }} / {{ no_of_js }}</span></div>
    </div>
  </div>

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

  <div class="footer">
    <span>Generated by PhishGuard</span>
    <span>{{ timestamp }}</span>
  </div>

</div>
</body>
</html>"""

_FALLBACK_ANALYSIS = {
    "risk_rating":        "MODERATE",
    "summary":            "Analysis could not be fully parsed. Please review the detection flags carefully.",
    "url_analysis":       "URL data was collected but structured LLM analysis is unavailable.",
    "whois_analysis":     "WHOIS data was collected but structured LLM analysis is unavailable.",
    "behaviour_analysis": "Page behaviour was logged but structured LLM analysis is unavailable.",
    "recommendations": [
        "Do not enter credentials on this page.",
        "Verify the domain name carefully before proceeding.",
        "Contact the website owner through a trusted channel to confirm legitimacy.",
    ],
}


def _build_context(data: URLRequest, result: AnalysisResult, refined: dict, whois: dict) -> str:
    flags = "\n".join(
        f"  - [{r.get('tier', '?')}] {r.get('text', '')}"
        for r in result.tagged_reasons
    ) or "  None"

    age = f"{whois['age_days']} days old" if whois.get("age_days") else "Unknown"
    if whois.get("age_days") and whois["age_days"] < 90:
        age += " (VERY NEW DOMAIN)"

    ns = ", ".join(whois.get("name_servers", [])[:3]) or "Unknown"

    return (
        f"VERDICT: {result.action} | {result.prediction} | {result.confidence}%\n"
        f"URL: {data.url}\n"
        f"Domain: {refined.get('registered_domain', data.domain)}\n"
        f"Title: {data.title or 'None'}\n"
        f"Protocol: {'HTTPS' if data.is_https else 'HTTP (INSECURE)'}\n"
        f"IP address: {'Yes (suspicious)' if refined.get('is_ip') else 'No'}\n"
        f"Subdomains: {refined.get('subdomain_count', 0)}\n"
        f"URL length: {len(data.url)} chars\n\n"
        f"WHOIS: Registrar={whois.get('registrar') or 'Unknown'}, "
        f"Country={whois.get('country') or 'Unknown'}\n"
        f"Created: {whois.get('created') or 'Unknown'}, "
        f"Expires: {whois.get('expires') or 'Unknown'}\n"
        f"Age: {age}, Name servers: {ns}\n\n"
        f"PAGE: Password field={'Yes' if data.has_password_field else 'No'}, "
        f"Hidden submission={'Yes' if data.is_hidden_submission else 'No'}\n"
        f"Cross-domain form={'Yes' if data.action_to_different_domain else 'No'}, "
        f"Social links={'Yes' if data.has_social_net else 'No'}\n"
        f"Copyright={'Yes' if data.has_copyright else 'No'}, "
        f"Images={data.no_of_images or 0}, Scripts={data.no_of_js or 0}\n"
        f"Bank keywords={'Yes' if data.has_bank_keywords else 'No'}, "
        f"Payment keywords={'Yes' if data.has_pay_keywords else 'No'}\n\n"
        f"FLAGS:\n{flags}"
    )


class ReportGenerator:

    def __init__(self, domain_intel: DomainIntelligence = None):
        self._whois = domain_intel or DomainIntelligence()

    def generate(
        self,
        data:    URLRequest,
        result:  AnalysisResult,
        refined: dict,
    ) -> tuple:
        """
        Returns (pdf_bytes | None, html_string).
        Raises ValueError if GROQ_API_KEY not set.
        """
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not set in environment")

        domain = refined.get("registered_domain", data.domain)
        logger.info(f"[REPORT] WHOIS lookup for {domain}")
        whois = self._whois.lookup(domain)

        context = _build_context(data, result, refined, whois)
        logger.info(f"[REPORT] Calling LLM ({len(context)} chars context)")
        analysis = self._call_llm(context)

        html = self._render_html(data, result, refined, whois, analysis)
        pdf_bytes = self._render_pdf(html)
        logger.info(f"[REPORT] Done — pdf={pdf_bytes is not None}, html={len(html)} chars")
        return pdf_bytes, html

    def _call_llm(self, context: str) -> dict:
        from langchain_groq import ChatGroq
        from langchain_core.messages import SystemMessage, HumanMessage

        llm = ChatGroq(
            model=MODEL,
            api_key=GROQ_API_KEY,
            temperature=0.2,
            max_tokens=1024,
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Analyse this security scan data and respond with JSON only:\n\n{context}"),
        ]

        response = llm.invoke(messages)
        raw = response.content.strip()

        # Strip markdown code fences if model wraps response
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1]
            if raw.endswith("```"):
                raw = raw.rsplit("```", 1)[0].strip()

        try:
            return json.loads(raw)
        except Exception as e:
            logger.warning(f"[REPORT] JSON parse failed ({e}) — using fallback")
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
            tagged_flags.append({"text": r.get("text", ""), "tier_cls": cls, "tier_label": lbl})

        age_days  = whois.get("age_days")
        whois_age = f"{age_days} days" if age_days else "Unknown"
        if age_days and age_days < 90:
            whois_age += " (very new)"

        domain    = refined.get("registered_domain", data.domain)
        url       = data.url
        url_short = url[:80] + "…" if len(url) > 80 else url
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        recs_raw        = analysis.get("recommendations", [])
        recommendations = list(enumerate(recs_raw, 1))

        ctx = {
            "domain":           domain,
            "url_short":        url_short,
            "timestamp":        timestamp,
            "result_action":    result.action,
            "risk_rating":      risk_rating,
            "header_colour":    header_colour,
            "risk_colour":      risk_colour,
            "confidence":       result.confidence,
            "summary":          analysis.get("summary", ""),
            "url_analysis":     analysis.get("url_analysis", ""),
            "whois_analysis":   analysis.get("whois_analysis", ""),
            "behaviour_analysis": analysis.get("behaviour_analysis", ""),
            "recommendations":  recommendations,
            "tagged_flags":     tagged_flags,
            "is_https":         data.is_https,
            "subdomain_count":  refined.get("subdomain_count", 0),
            "url_length":       len(data.url),
            "is_ip":            refined.get("is_ip", False),
            "whois_registrar":  whois.get("registrar") or "Unknown",
            "whois_country":    whois.get("country") or "Unknown",
            "whois_created":    whois.get("created") or "Unknown",
            "whois_expires":    whois.get("expires") or "Unknown",
            "whois_age":        whois_age,
            "whois_ns":         ", ".join((whois.get("name_servers") or [])[:2]) or "Unknown",
            "has_password":     data.has_password_field,
            "is_hidden_submission":       data.is_hidden_submission,
            "action_to_different_domain": data.action_to_different_domain,
            "has_social_net":   data.has_social_net,
            "has_copyright":    data.has_copyright,
            "no_of_images":     data.no_of_images or 0,
            "no_of_js":         data.no_of_js or 0,
        }

        return Template(_HTML_TEMPLATE).render(**ctx)

    @staticmethod
    def _render_pdf(html: str):
        try:
            from weasyprint import HTML as WP_HTML
            return WP_HTML(string=html).write_pdf()
        except ImportError:
            logger.info("[REPORT] WeasyPrint not installed — PDF unavailable")
            return None
        except Exception as e:
            logger.warning(f"[REPORT] WeasyPrint render error: {e}")
            return None
