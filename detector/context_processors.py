from django.db.models import Avg, Count
from django.utils import timezone

from .models import EmailScan


def scan_stats(request):
    """Global stats for the stats bar on every page."""
    today = timezone.now().date()
    qs = EmailScan.objects.all()
    total = qs.count()
    avg_score = qs.aggregate(avg=Avg('phishing_probability'))['avg'] or 0
    phishing_today = qs.filter(
        created_at__date=today,
        phishing_probability__gte=61,
    ).count()
    recent = qs[:10]
    return {
        'stats_total': total,
        'stats_avg_score': round(avg_score, 1),
        'stats_phishing_today': phishing_today,
        'recent_scans': recent,
    }
