from django.urls import path

from . import consumers

websocket_urlpatterns = [
    path('ws/alerts/', consumers.AlertConsumer.as_asgi()),
    path('ws/cases/', consumers.CaseConsumer.as_asgi()),
    path('ws/timeline/', consumers.CaseConsumer.as_asgi()),  # Reusa o CaseConsumer para timeline
] 