"""
ReportGenerator — LLM-powered phishing analysis report.

Pipeline:
  1. Collect all available data (analysis result, page features, WHOIS)
  2. Run additional heuristic checks for report context
  3. Build a rich structured prompt
  4. Send to Groq via LangChain (llama-3.3-70b-versatile)
  5. Return HTML report string

The prompt is designed to produce a professional, user-friendly
security report — not just a dump of raw data.
"""

import logging
import os
from datetime import datetime

from models.models import URLRequest, AnalysisResult
from utils.whois_lookup import DomainIntelligence

logger = logging.getLogger("PhishGuard")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
MODEL        = "llama-3.3-70b-versatile"


def _build_context(
    data:     URLRequest,
    result:   AnalysisResult,
    refined:  dict,
    whois:    dict,
) -> str:
    """Build the structured context block fed into the LLM prompt."""

    flags = "\n".join(
        f"  - [{r.get('tier','?')}] {r.get('text','')}"
        for r in result.tagged_reasons
    ) or "  None"

    age = f"{whois['age_days']} days old" if whois.get("age_days") else "Unknown"
    if whois.get("age_days") and whois["age_days"] < 90:
        age += " ⚠️ VERY NEW DOMAIN"

    ns = ", ".join(whois.get("name_servers", [])[:3]) or "Unknown"

    return f"""
=== PHISHGUARD ANALYSIS REPORT CONTEXT ===

VERDICT
  Decision:    {result.action}
  Prediction:  {result.prediction}
  Confidence:  {result.confidence}%
  Analysed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

URL DETAILS
  Full URL:    {data.url}
  Domain:      {refined.get('registered_domain', data.domain)}
  Page title:  {data.title or 'None'}
  Protocol:    {'HTTPS ✓' if data.is_https else 'HTTP ⚠️ INSECURE'}
  IP address:  {'Yes ⚠️' if refined.get('is_ip') else 'No'}
  Subdomains:  {refined.get('subdomain_count', 0)}
  URL length:  {len(data.url)} characters

DOMAIN INTELLIGENCE (WHOIS)
  Registrar:   {whois.get('registrar') or 'Unknown'}
  Country:     {whois.get('country') or 'Unknown'}
  Created:     {whois.get('created') or 'Unknown'}
  Expires:     {whois.get('expires') or 'Unknown'}
  Domain age:  {age}
  Name servers:{ns}
  WHOIS error: {whois.get('error') or 'None'}

PAGE FEATURES
  Password field:      {'Yes' if data.has_password_field else 'No'}
  Hidden submission:   {'Yes ⚠️' if data.is_hidden_submission else 'No'}
  Cross-domain form:   {'Yes ⚠️' if data.action_to_different_domain else 'No'}
  Hidden fields:       {'Yes' if data.has_hidden_fields else 'No'}
  Submit button:       {'Yes' if data.has_submit_button else 'No'}
  Has favicon:         {'Yes' if data.has_favicon else 'No'}
  Has description:     {'Yes' if data.has_description else 'No'}
  Has copyright info:  {'Yes' if data.has_copyright else 'No'}
  Social media links:  {'Yes' if data.has_social_net else 'No'}
  Self-referencing:    {data.no_of_self_ref or 0} links
  Images:              {data.no_of_images or 0}
  Scripts:             {data.no_of_js or 0}
  Stylesheets:         {data.no_of_css or 0}
  Total anchors:       {data.total_anchors}
  Empty anchors:       {data.empty_anchors}
  Bank keywords:       {'Yes' if data.has_bank_keywords else 'No'}
  Payment keywords:    {'Yes' if data.has_pay_keywords else 'No'}
  Crypto keywords:     {'Yes' if data.has_crypto_keywords else 'No'}

DETECTION FLAGS
{flags}

URL STRUCTURE ANALYSIS
  Obfuscation ratio:   {refined.get('ObfuscationRatio', 0):.4f}
  Digit ratio:         {refined.get('DegitRatioInURL', 0):.4f}
  Letter ratio:        {refined.get('LetterRatioInURL', 0):.4f}
  Special char ratio:  {refined.get('SpacialCharRatioInURL', 0):.4f}
  External link ratio: {refined.get('ExternalRatio', 0):.4f}
  Has domain dashes:   {'Yes' if refined.get('HasDomainDashes') else 'No'}
"""


SYSTEM_PROMPT = """You are a senior cybersecurity analyst specialising in phishing detection.
Your task is to write a clear, professional, and user-friendly security report based on the
technical analysis data provided. The report is for a non-technical end user who wants to
understand whether a website they visited is safe.

Report requirements:
- Write in plain English, avoid jargon where possible
- Be decisive — give a clear recommendation
- Explain WHY something is suspicious, not just THAT it is
- Highlight the most important risk factors prominently
- Include a domain age assessment — new domains (< 90 days) are a major red flag
- Assess the WHOIS data for signs of suspicious registration patterns
- Comment on the page structure and what it reveals about intent
- Give a final Risk Rating: SAFE / LOW RISK / MODERATE RISK / HIGH RISK / CRITICAL
- End with 3 clear bullet point recommendations for the user

Format the report in clean HTML with inline CSS. Use a professional layout with:
- A header showing the domain and verdict
- Colour-coded risk badge (green/amber/orange/red based on rating)
- Sections: Executive Summary, URL Analysis, Domain Intelligence, Page Behaviour, Detection Flags, Conclusion & Recommendations
- A footer with the analysis timestamp and "Generated by PhishGuard"

Keep the HTML self-contained with all CSS inline so it can be saved as a standalone file."""


USER_PROMPT_TEMPLATE = """Please generate a security report for the following analysis data:

{context}

Generate a complete, self-contained HTML report with inline CSS that a non-technical user
can read and understand. Be thorough but concise. If the domain is very new (under 90 days)
or has suspicious WHOIS characteristics, flag this prominently."""


class ReportGenerator:

    def __init__(self, domain_intel: DomainIntelligence = None):
        self._whois = domain_intel or DomainIntelligence()

    def generate(
        self,
        data:    URLRequest,
        result:  AnalysisResult,
        refined: dict,
    ) -> str:
        """
        Generates a full HTML security report.
        Returns HTML string. Raises if Groq API key not set.
        """
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not set in environment")

        # Gather WHOIS
        domain = refined.get("registered_domain", data.domain)
        logger.info(f"[REPORT] WHOIS lookup for {domain}")
        whois  = self._whois.lookup(domain)

        # Build context
        context = _build_context(data, result, refined, whois)
        logger.info(f"[REPORT] Context built ({len(context)} chars) — calling Groq")

        # Call Groq via LangChain
        html = self._call_llm(context)
        logger.info(f"[REPORT] Report generated ({len(html)} chars)")
        return html

    def _call_llm(self, context: str) -> str:
        from langchain_groq import ChatGroq
        from langchain_core.prompts import ChatPromptTemplate

        llm = ChatGroq(
            model=MODEL,
            api_key=GROQ_API_KEY,
            temperature=0.3,      # low temp for consistent, factual reports
            max_tokens=4096,
        )

        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            ("human",  USER_PROMPT_TEMPLATE),
        ])

        chain  = prompt | llm
        result = chain.invoke({"context": context})
        html   = result.content

        # Strip markdown code fences if model wraps in ```html
        html = html.strip()
        if html.startswith("```"):
            html = html.split("\n", 1)[-1]
            if html.endswith("```"):
                html = html.rsplit("```", 1)[0]

        return html.strip()
