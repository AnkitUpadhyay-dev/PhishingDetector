"""
Parse raw email content (plain text, RFC822 headers, or .eml) into structured fields.
"""
import re
import email
from email import policy
from email.utils import parseaddr, getaddresses
from typing import Any

from bs4 import BeautifulSoup

# URL pattern for plain-text bodies
URL_RE = re.compile(
    r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+',
    re.IGNORECASE,
)

# Common urgency / action keywords
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'act now', 'verify', 'suspend', 'suspended',
    'expire', 'expires', 'within 24 hours', 'confirm your', 'click here',
    'unusual activity', 'compromised', 'locked', 'limited time', 'asap',
    'final notice', 'action required', 'update your', 'verify your account',
]


def _extract_email_address(header_value: str) -> str:
    """Return the email portion from a From/Reply-To header."""
    if not header_value:
        return ''
    _, addr = parseaddr(header_value)
    return addr.lower().strip()


def _domain(addr: str) -> str:
    if '@' in addr:
        return addr.split('@', 1)[1].lower()
    return ''


def _decode_payload(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return part.get_payload() or ''
    charset = part.get_content_charset() or 'utf-8'
    try:
        return payload.decode(charset, errors='replace')
    except (LookupError, AttributeError):
        return payload.decode('utf-8', errors='replace')


def _walk_parts(msg) -> tuple[str, str]:
    """Return (plain_text, html) from multipart message."""
    plain, html = '', ''
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_disposition() == 'attachment':
                continue
            if ctype == 'text/plain' and not plain:
                plain = _decode_payload(part)
            elif ctype == 'text/html' and not html:
                html = _decode_payload(part)
    else:
        ctype = msg.get_content_type()
        body = _decode_payload(msg)
        if ctype == 'text/html':
            html = body
        else:
            plain = body
    return plain, html


def _links_from_html(html: str) -> list[dict[str, str]]:
    links = []
    if not html:
        return links
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup.find_all('a', href=True):
        href = tag['href'].strip()
        if href.startswith(('http://', 'https://', 'www.')):
            links.append({
                'url': href if href.startswith('http') else f'https://{href}',
                'display_text': tag.get_text(strip=True) or href,
            })
    return links


def _links_from_text(text: str) -> list[str]:
    found = URL_RE.findall(text or '')
    normalized = []
    for u in found:
        if u.lower().startswith('www.'):
            u = 'https://' + u
        if u not in normalized:
            normalized.append(u)
    return normalized


def _find_urgency_keywords(text: str) -> list[str]:
    lower = (text or '').lower()
    return [kw for kw in URGENCY_KEYWORDS if kw in lower]


def parse_raw_email(raw_content: str) -> dict[str, Any]:
    """
    Parse pasted or uploaded email into a dict used by the AI engine and UI.
    """
    raw_content = (raw_content or '').strip()
    if not raw_content:
        return {
            'subject': '',
            'sender': '',
            'sender_name': '',
            'reply_to': '',
            'body': '',
            'html_body': '',
            'links': [],
            'link_objects': [],
            'urgency_keywords': [],
            'reply_to_mismatch': False,
            'headers_present': False,
        }

    # Try RFC822 parse; fall back to plain text
    try:
        msg = email.message_from_string(raw_content, policy=policy.default)
    except Exception:
        msg = None

    headers_present = bool(msg and msg.get('From'))

    if headers_present:
        subject = msg.get('Subject', '') or ''
        from_header = msg.get('From', '') or ''
        reply_to_header = msg.get('Reply-To', '') or ''
        sender_name, sender_addr = parseaddr(from_header)
        sender = sender_addr or from_header
        reply_to = _extract_email_address(reply_to_header)
        plain, html = _walk_parts(msg)
    else:
        subject = ''
        from_header = ''
        reply_to_header = ''
        sender_name, sender = '', ''
        reply_to = ''
        plain, html = raw_content, ''
        # Heuristic: user pasted headers inline
        for line in raw_content.splitlines()[:20]:
            if line.lower().startswith('subject:'):
                subject = line.split(':', 1)[1].strip()
            elif line.lower().startswith('from:'):
                from_header = line.split(':', 1)[1].strip()
                sender_name, sender = parseaddr(from_header)
                sender = sender or from_header
            elif line.lower().startswith('reply-to:'):
                reply_to_header = line.split(':', 1)[1].strip()
                reply_to = _extract_email_address(reply_to_header)
        if subject or from_header:
            headers_present = True
            # Strip header block from body for display
            body_lines = []
            in_body = False
            for line in raw_content.splitlines():
                if not in_body and line.strip() == '':
                    in_body = True
                    continue
                if in_body:
                    body_lines.append(line)
            plain = '\n'.join(body_lines) if body_lines else raw_content

    body = plain.strip() or BeautifulSoup(html, 'html.parser').get_text(separator='\n', strip=True) if html else raw_content

    link_objects = _links_from_html(html)
    text_urls = _links_from_text(body)
    seen_urls = {lo['url'] for lo in link_objects}
    for u in text_urls:
        if u not in seen_urls:
            link_objects.append({'url': u, 'display_text': u})
            seen_urls.add(u)

    sender_email = _extract_email_address(sender) if sender else ''
    reply_to_domain = _domain(reply_to)
    sender_domain = _domain(sender_email)
    reply_to_mismatch = bool(
        reply_to and sender_email
        and reply_to_domain != sender_domain
    )

    return {
        'subject': subject,
        'sender': sender_email or sender or from_header,
        'sender_name': sender_name,
        'from_header': from_header,
        'reply_to': reply_to or reply_to_header,
        'body': body,
        'html_body': html,
        'links': [lo['url'] for lo in link_objects],
        'link_objects': link_objects,
        'urgency_keywords': _find_urgency_keywords(body),
        'reply_to_mismatch': reply_to_mismatch,
        'headers_present': headers_present,
    }


def parse_eml_file(file_obj) -> str:
    """Read uploaded .eml file bytes as string."""
    content = file_obj.read()
    if isinstance(content, bytes):
        return content.decode('utf-8', errors='replace')
    return str(content)
