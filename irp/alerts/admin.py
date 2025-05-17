from django.contrib import admin
from .models import (
    AlertSeverity, AlertStatus, Alert, AlertComment,
    AlertCustomFieldDefinition, AlertCustomFieldValue,
    AlertObservable
)

# Register alert models
admin.site.register(AlertSeverity)
admin.site.register(AlertStatus)
admin.site.register(Alert)
admin.site.register(AlertComment)
admin.site.register(AlertCustomFieldDefinition)
admin.site.register(AlertCustomFieldValue)
admin.site.register(AlertObservable)
