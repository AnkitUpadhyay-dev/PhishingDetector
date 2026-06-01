import re
from django import template
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter
def highlight_email(body, parsed):
    """Highlight suspicious links, urgency keywords, and sender in email preview."""
    if not body:
        return ''
    text = str(body)

    # Escape HTML first
    text = (
        text.replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
    )

    if isinstance(parsed, dict):
        for kw in parsed.get('urgency_keywords', []):
            if kw:
                pattern = re.compile(re.escape(kw), re.IGNORECASE)
                text = pattern.sub(
                    lambda m: f'<span class="hl-urgency">{m.group(0)}</span>',
                    text,
                )
        for lo in parsed.get('link_objects', []):
            url = lo.get('url', '')
            if url:
                pattern = re.compile(re.escape(url), re.IGNORECASE)
                text = pattern.sub(
                    lambda m: f'<span class="hl-link">{m.group(0)}</span>',
                    text,
                )
        sender = parsed.get('sender', '')
        if sender:
            pattern = re.compile(re.escape(sender), re.IGNORECASE)
            text = pattern.sub(
                lambda m: f'<span class="hl-sender">{m.group(0)}</span>',
                text,
            )

    return mark_safe(text.replace('\n', '<br>'))


@register.filter
def score_level(score):
    score = int(score or 0)
    if score <= 30:
        return 'safe'
    if score <= 45:
        return 'low'
    if score <= 60:
        return 'medium'
    if score <= 85:
        return 'high'
    return 'critical'
