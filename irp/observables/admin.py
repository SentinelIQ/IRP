from django.contrib import admin
from .models import ObservableType, TLPLevel, PAPLevel, Observable

# Register observable models
admin.site.register(ObservableType)
admin.site.register(TLPLevel)
admin.site.register(PAPLevel)
admin.site.register(Observable)
