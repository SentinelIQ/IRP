from django.contrib import admin
from .models import MitreTactic, MitreTechnique, TechniqueTactic

@admin.register(MitreTactic)
class MitreTacticAdmin(admin.ModelAdmin):
    list_display = ('tactic_id', 'name', 'version')
    search_fields = ('tactic_id', 'name')
    list_filter = ('version',)

@admin.register(MitreTechnique)
class MitreTechniqueAdmin(admin.ModelAdmin):
    list_display = ('technique_id', 'name', 'is_subtechnique', 'parent_technique', 'version')
    search_fields = ('technique_id', 'name', 'description')
    list_filter = ('is_subtechnique', 'version')

@admin.register(TechniqueTactic)
class TechniqueTacticAdmin(admin.ModelAdmin):
    list_display = ('technique', 'tactic')
    search_fields = ('technique__name', 'tactic__name')
    autocomplete_fields = ('technique', 'tactic')
