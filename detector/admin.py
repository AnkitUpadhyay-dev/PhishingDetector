from django.contrib import admin
from .models import EmailScan


@admin.register(EmailScan)
class EmailScanAdmin(admin.ModelAdmin):
    list_display = ('subject', 'sender', 'threat_level', 'phishing_probability', 'created_at')
    list_filter = ('threat_level', 'created_at')
    search_fields = ('subject', 'sender', 'summary')
    readonly_fields = ('id', 'created_at', 'analysis_json', 'parsed_email')
