from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('analyze/', views.analyze, name='analyze'),
    path('history/', views.history, name='history'),
    path('scan/<uuid:scan_id>/', views.results, name='results'),
    path('scan/<uuid:scan_id>/export/', views.export_json, name='export_json'),
]
