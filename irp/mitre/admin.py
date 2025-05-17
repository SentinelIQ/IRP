from django.contrib import admin
from .models import MitreTactic, MitreTechnique, TechniqueTactic, CaseMitreTechnique, AlertMitreTechnique

class TechniqueTacticInline(admin.TabularInline):
    model = TechniqueTactic
    extra = 1
    autocomplete_fields = ('technique', 'tactic')

@admin.register(MitreTactic)
class MitreTacticAdmin(admin.ModelAdmin):
    list_display = ('tactic_id', 'name', 'short_name', 'version')
    search_fields = ('tactic_id', 'name', 'short_name')
    list_filter = ('version',)
    inlines = [TechniqueTacticInline]

@admin.register(MitreTechnique)
class MitreTechniqueAdmin(admin.ModelAdmin):
    list_display = ('technique_id', 'name', 'is_subtechnique', 'parent_technique', 'version', 'display_tactics')
    search_fields = ('technique_id', 'name', 'description')
    list_filter = ('is_subtechnique', 'version', 'tactics')
    inlines = [TechniqueTacticInline]
    
    def display_tactics(self, obj):
        return ", ".join([tactic.name for tactic in obj.tactics.all()])
    display_tactics.short_description = "Táticas"

@admin.register(TechniqueTactic)
class TechniqueTacticAdmin(admin.ModelAdmin):
    list_display = ('technique', 'tactic', 'display_technique_id', 'display_tactic_id')
    search_fields = ('technique__name', 'technique__technique_id', 'tactic__name', 'tactic__tactic_id')
    autocomplete_fields = ('technique', 'tactic')
    list_filter = ('tactic', 'technique__is_subtechnique')
    
    def display_technique_id(self, obj):
        return obj.technique.technique_id
    display_technique_id.short_description = "Technique ID"
    
    def display_tactic_id(self, obj):
        return obj.tactic.tactic_id
    display_tactic_id.short_description = "Tactic ID"

@admin.register(CaseMitreTechnique)
class CaseMitreTechniqueAdmin(admin.ModelAdmin):
    list_display = ('case', 'technique', 'kill_chain_phase', 'confidence_score', 'impact_level', 'added_by', 'added_at')
    search_fields = ('case__title', 'technique__name', 'technique__technique_id', 'kill_chain_phase')
    autocomplete_fields = ('technique',)
    list_filter = ('kill_chain_phase', 'impact_level', 'mitigation_status', 'technique__tactics')
    readonly_fields = ('added_at',)
    fieldsets = (
        ('Relação Caso-Técnica', {
            'fields': ('case', 'technique', 'added_by', 'added_at', 'notes')
        }),
        ('Detalhes da Kill Chain', {
            'fields': ('kill_chain_phase', 'first_observed', 'last_observed')
        }),
        ('Análise e Mitigação', {
            'fields': ('confidence_score', 'detection_method', 'artifacts', 'impact_level', 'mitigation_status')
        }),
    )

@admin.register(AlertMitreTechnique)
class AlertMitreTechniqueAdmin(admin.ModelAdmin):
    list_display = ('alert', 'technique', 'added_by', 'added_at')
    search_fields = ('alert__title', 'technique__name', 'technique__technique_id')
    autocomplete_fields = ('technique',)
    readonly_fields = ('added_at',)
