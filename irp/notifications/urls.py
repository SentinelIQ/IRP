from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    NotificationEventViewSet, NotificationChannelViewSet,
    NotificationRuleViewSet, NotificationLogViewSet, NotificationViewSet
)

router = DefaultRouter()
router.register(r'notification-events', NotificationEventViewSet)
router.register(r'notification-channels', NotificationChannelViewSet, basename='notification-channel')
router.register(r'notification-rules', NotificationRuleViewSet, basename='notification-rule')
router.register(r'notification-logs', NotificationLogViewSet, basename='notification-log')
router.register(r'notifications', NotificationViewSet, basename='notification')

urlpatterns = [
    path('', include(router.urls)),
] 