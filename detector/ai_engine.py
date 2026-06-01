"""
AI analysis engine — Gemini (primary) or OpenAI with structured JSON output.
"""
import json
import re
import logging
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are a world-class cybersecurity AI specializing in phishing email detection.
Analyze the provided email and return ONLY a valid JSON object (no markdown, no explanation outside JSON).
Be precise, evidence-based, and quote exact phrases from the email as evidence.
Score all values from 0-100 where 100 = maximum threat.

Return JSON with this exact schema:
{
  "phishing_probability": <int 0-100>,
  "threat_level": "<SAFE|LOW|MEDIUM|HIGH|CRITICAL>",
  "ai_confidence": <int 0-100>,
  "summary": "<one line summary>",
  "why_dangerous": "<full paragraph explaining danger>",
  "indicators": {
    "urgency_manipulation": {"score": <int>, "evidence": [<strings>], "explanation": "<string>"},
    "spoofing_signs": {"score": <int>, "evidence": [<strings>], "explanation": "<string>"},
    "suspicious_links": {"score": <int>, "evidence": [<strings>], "explanation": "<string>"},
    "emotional_triggers": {"score": <int>, "evidence": [<strings>], "explanation": "<string>"},
    "sender_legitimacy": {"score": <int>, "evidence": [<strings>], "explanation": "<string>"},
    "overall_threat": {"score": <int>, "evidence": [<strings>], "explanation": "<string>"}
  },
  "extracted_links": [
    {"url": "<string>", "display_text": "<string>", "is_suspicious": <bool>, "reason": "<string>"}
  ],
  "recommendations": [<strings>]
}
"""

JSON_SCHEMA_HINT = """
Threat level mapping: 0-30 SAFE, 31-45 LOW, 46-60 MEDIUM, 61-85 HIGH, 86-100 CRITICAL.
phishing_probability should align with overall threat.
"""


def build_analysis_prompt(parsed_email: dict) -> str:
    links = parsed_email.get('links', [])
    urgency = parsed_email.get('urgency_keywords', [])
    mismatch = parsed_email.get('reply_to_mismatch', False)

    return f"""
Analyze this email for phishing indicators:

SUBJECT: {parsed_email.get('subject', 'N/A')}
FROM: {parsed_email.get('sender', 'N/A')}
SENDER NAME: {parsed_email.get('sender_name', 'N/A')}
REPLY-TO: {parsed_email.get('reply_to', 'Not present')}
REPLY-TO DOMAIN MISMATCH: {mismatch}
EXTRACTED LINKS: {links}
DETECTED URGENCY KEYWORDS: {urgency}
EMAIL BODY:
{parsed_email.get('body', '')}

{JSON_SCHEMA_HINT}
Return the JSON analysis following the exact schema provided.
"""


def _extract_json(text: str) -> dict:
    """Parse JSON from model response, stripping markdown fences if present."""
    text = (text or '').strip()
    fence = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
    if fence:
        text = fence.group(1).strip()
    # Find outermost JSON object
    start = text.find('{')
    end = text.rfind('}')
    if start >= 0 and end > start:
        text = text[start:end + 1]
    return json.loads(text)


def _normalize_analysis(data: dict, parsed_email: dict) -> dict:
    """Ensure required keys and valid threat levels."""
    levels = {'SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
    prob = int(data.get('phishing_probability', 0))
    prob = max(0, min(100, prob))

    threat = str(data.get('threat_level', 'SAFE')).upper()
    if threat not in levels:
        if prob <= 30:
            threat = 'SAFE'
        elif prob <= 45:
            threat = 'LOW'
        elif prob <= 60:
            threat = 'MEDIUM'
        elif prob <= 85:
            threat = 'HIGH'
        else:
            threat = 'CRITICAL'

    indicators = data.get('indicators') or {}
    default_indicator = {'score': 0, 'evidence': [], 'explanation': 'No significant indicators detected.'}
    for key in (
        'urgency_manipulation', 'spoofing_signs', 'suspicious_links',
        'emotional_triggers', 'sender_legitimacy', 'overall_threat',
    ):
        if key not in indicators:
            indicators[key] = dict(default_indicator)

    links = data.get('extracted_links') or []
    if not links and parsed_email.get('link_objects'):
        links = [
            {
                'url': lo['url'],
                'display_text': lo.get('display_text', lo['url']),
                'is_suspicious': None,
                'reason': 'Pending review',
            }
            for lo in parsed_email['link_objects']
        ]

    return {
        'phishing_probability': prob,
        'threat_level': threat,
        'ai_confidence': max(0, min(100, int(data.get('ai_confidence', 85)))),
        'summary': data.get('summary', 'Analysis complete.'),
        'why_dangerous': data.get('why_dangerous', ''),
        'indicators': indicators,
        'extracted_links': links,
        'recommendations': data.get('recommendations') or [
            'Do not click any links in this email',
            'Report to your IT security team',
            'Delete the email if confirmed phishing',
        ],
    }


def _call_gemini(prompt: str) -> str:
    import google.generativeai as genai

    api_key = settings.GEMINI_API_KEY
    if not api_key:
        raise ValueError('GEMINI_API_KEY is not configured in .env')

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        settings.GEMINI_MODEL,
        system_instruction=SYSTEM_PROMPT,
    )
    response = model.generate_content(
        prompt,
        generation_config={'temperature': 0.2, 'response_mime_type': 'application/json'},
    )
    return response.text


def _call_openai(prompt: str) -> str:
    from openai import OpenAI

    api_key = settings.OPENAI_API_KEY
    if not api_key:
        raise ValueError('OPENAI_API_KEY is not configured in .env')

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model='gpt-4o',
        messages=[
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': prompt},
        ],
        temperature=0.2,
        response_format={'type': 'json_object'},
    )
    return response.choices[0].message.content


def _mock_analysis(parsed_email: dict) -> dict:
    """Fallback when no API key — heuristic demo for development."""
    body = (parsed_email.get('body') or '').lower()
    links = parsed_email.get('links', [])
    mismatch = parsed_email.get('reply_to_mismatch', False)
    urgency = parsed_email.get('urgency_keywords', [])

    score = 15
    if urgency:
        score += min(30, len(urgency) * 8)
    if mismatch:
        score += 25
    if links:
        score += min(25, len(links) * 10)
    if any(x in body for x in ('password', 'verify', 'suspended', 'click here')):
        score += 20
    score = min(100, score)

    if score <= 30:
        threat = 'SAFE'
    elif score <= 45:
        threat = 'LOW'
    elif score <= 60:
        threat = 'MEDIUM'
    elif score <= 85:
        threat = 'HIGH'
    else:
        threat = 'CRITICAL'

    return {
        'phishing_probability': score,
        'threat_level': threat,
        'ai_confidence': 72,
        'summary': 'Heuristic analysis (configure GEMINI_API_KEY for full AI analysis).',
        'why_dangerous': (
            'This assessment used local heuristics because no AI API key was configured. '
            'Indicators include urgency language, link patterns, and sender anomalies when present.'
        ),
        'indicators': {
            'urgency_manipulation': {
                'score': min(100, len(urgency) * 25),
                'evidence': urgency[:5],
                'explanation': 'Urgency keywords pressure quick action without verification.',
            },
            'spoofing_signs': {
                'score': 80 if mismatch else 10,
                'evidence': ['Reply-To domain differs from From'] if mismatch else [],
                'explanation': 'Reply-To mismatch is a common phishing technique.' if mismatch else 'No spoofing signals detected.',
            },
            'suspicious_links': {
                'score': min(100, len(links) * 30),
                'evidence': links[:5],
                'explanation': 'URLs should be verified against claimed brand domains.',
            },
            'emotional_triggers': {
                'score': 40 if any(w in body for w in ('compromised', 'unusual', 'locked')) else 10,
                'evidence': [],
                'explanation': 'Fear-based language may indicate social engineering.',
            },
            'sender_legitimacy': {
                'score': 30 if mismatch else 50,
                'evidence': [parsed_email.get('sender', '')],
                'explanation': 'Verify sender domain against expected organization.',
            },
            'overall_threat': {
                'score': score,
                'evidence': [f'Composite score: {score}%'],
                'explanation': 'Aggregated threat based on available signals.',
            },
        },
        'extracted_links': [
            {
                'url': lo['url'],
                'display_text': lo.get('display_text', lo['url']),
                'is_suspicious': True,
                'reason': 'Review domain authenticity',
            }
            for lo in parsed_email.get('link_objects', [])
        ],
        'recommendations': [
            'Configure GEMINI_API_KEY in .env for AI-powered analysis',
            'Do not click suspicious links',
            'Report to IT security if unsure',
        ],
    }


def analyze_email(parsed_email: dict) -> dict[str, Any]:
    """
    Run AI analysis on parsed email dict. Returns normalized analysis JSON.
    """
    prompt = build_analysis_prompt(parsed_email)
    provider = (settings.AI_PROVIDER or 'gemini').lower()

    has_gemini = bool(settings.GEMINI_API_KEY)
    has_openai = bool(settings.OPENAI_API_KEY)

    if not has_gemini and not has_openai:
        logger.warning('No AI API keys configured; using heuristic mock analysis.')
        return _normalize_analysis(_mock_analysis(parsed_email), parsed_email)

    raw_text = ''
    try:
        if provider == 'openai' and has_openai:
            raw_text = _call_openai(prompt)
        elif has_gemini:
            raw_text = _call_gemini(prompt)
        elif has_openai:
            raw_text = _call_openai(prompt)
        data = _extract_json(raw_text)
        return _normalize_analysis(data, parsed_email)
    except Exception as exc:
        logger.exception('AI analysis failed: %s', exc)
        mock = _mock_analysis(parsed_email)
        mock['summary'] = f'AI analysis failed ({exc}). Showing heuristic results.'
        return _normalize_analysis(mock, parsed_email)
