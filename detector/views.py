import json
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods
from .models import EmailScan
from .email_parser import parse_raw_email, parse_eml_file
from .ai_engine import analyze_email

# Indicator card metadata for templates
INDICATOR_CARDS = [
    ('urgency_manipulation', 'Urgency Manipulation', '🕐'),
    ('spoofing_signs', 'Sender Spoofing', '👤'),
    ('suspicious_links', 'Suspicious Links', '🔗'),
    ('emotional_triggers', 'Emotional Triggers', '😨'),
    ('sender_legitimacy', 'Sender Legitimacy', '📧'),
    ('overall_threat', 'Overall Threat Score', '🧠'),
]


def _save_scan(raw_email: str, parsed: dict, analysis: dict) -> EmailScan:
    return EmailScan.objects.create(
        raw_email=raw_email,
        subject=parsed.get('subject', '')[:500],
        sender=(parsed.get('sender') or '')[:300],
        phishing_probability=analysis['phishing_probability'],
        threat_level=analysis['threat_level'],
        analysis_json=analysis,
        summary=analysis.get('summary', ''),
        why_dangerous=analysis.get('why_dangerous', ''),
        ai_confidence=analysis.get('ai_confidence', 0),
        parsed_email=parsed,
    )


def _build_results_context(scan: EmailScan):
    analysis = scan.analysis_json or {}
    indicators = analysis.get('indicators', {})
    cards = []
    for key, label, icon in INDICATOR_CARDS:
        ind = indicators.get(key, {})
        cards.append({
            'key': key,
            'label': label,
            'icon': icon,
            'score': ind.get('score', 0),
            'evidence': ind.get('evidence', []),
            'explanation': ind.get('explanation', ''),
        })
    return {
        'scan': scan,
        'analysis': analysis,
        'cards': cards,
        'parsed': scan.parsed_email or {},
    }


def index(request):
    return render(request, 'detector/index.html')


def history(request):
    scans = EmailScan.objects.all()[:50]
    return render(request, 'detector/history.html', {'scans': scans})


def results(request, scan_id):
    scan = get_object_or_404(EmailScan, pk=scan_id)
    ctx = _build_results_context(scan)
    return render(request, 'detector/results.html', ctx)


@require_http_methods(['POST'])
def analyze(request):
    """Analyze email — supports form POST (redirect) and JSON/fetch API."""
    raw_email = request.POST.get('raw_email', '').strip()
    eml_file = request.FILES.get('eml_file')

    if eml_file:
        raw_email = parse_eml_file(eml_file)

    if not raw_email:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json':
            return JsonResponse({'error': 'No email content provided.'}, status=400)
        return redirect('index')

    parsed = parse_raw_email(raw_email)
    analysis = analyze_email(parsed)
    scan = _save_scan(raw_email, parsed, analysis)

    wants_json = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or request.POST.get('format') == 'json'
        or 'application/json' in request.headers.get('Accept', '')
    )

    if wants_json:
        return JsonResponse({
            'scan_id': str(scan.id),
            'redirect_url': request.build_absolute_uri(
                scan.get_absolute_url() if hasattr(scan, 'get_absolute_url') else f'/scan/{scan.id}/'
            ),
            'analysis': analysis,
        })

    return redirect('results', scan_id=scan.id)


def export_json(request, scan_id):
    scan = get_object_or_404(EmailScan, pk=scan_id)
    payload = {
        'id': str(scan.id),
        'created_at': scan.created_at.isoformat(),
        'subject': scan.subject,
        'sender': scan.sender,
        'phishing_probability': scan.phishing_probability,
        'threat_level': scan.threat_level,
        'analysis': scan.analysis_json,
    }
    response = HttpResponse(
        json.dumps(payload, indent=2),
        content_type='application/json',
    )
    response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}.json"'
    return response
