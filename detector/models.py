import uuid
from django.db import models
from django.utils import timezone


class EmailScan(models.Model):
    THREAT_LEVELS = [
        ('SAFE', 'Safe'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    raw_email = models.TextField()
    subject = models.CharField(max_length=500, blank=True)
    sender = models.CharField(max_length=300, blank=True)
    phishing_probability = models.IntegerField(default=0)
    threat_level = models.CharField(max_length=20, choices=THREAT_LEVELS, default='SAFE')
    analysis_json = models.JSONField(default=dict)
    summary = models.TextField(blank=True)
    why_dangerous = models.TextField(blank=True)
    ai_confidence = models.IntegerField(default=0)
    parsed_email = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.subject or "No subject"} — {self.threat_level} ({self.phishing_probability}%)'

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('results', kwargs={'scan_id': self.pk})

    @property
    def is_phishing_today(self):
        today = timezone.now().date()
        return (
            self.created_at.date() == today
            and self.phishing_probability >= 61
        )
