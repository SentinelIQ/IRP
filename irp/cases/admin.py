from django.contrib import admin
from .models import (
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment,
    CaseCustomFieldDefinition, CaseCustomFieldValue, Task,
    TaskStatus, CaseObservable, CaseMitreTechnique
)

@admin.register(CaseSeverity)
class CaseSeverityAdmin(admin.ModelAdmin):
    list_display = ('name', 'level_order', 'color_code')
    search_fields = ('name',)
    ordering = ('level_order',)

@admin.register(CaseStatus)
class CaseStatusAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'is_default_open_status', 'is_terminal_status', 'color_code')
    search_fields = ('name',)
    list_filter = ('is_default_open_status', 'is_terminal_status', 'organization')

@admin.register(CaseTemplate)
class CaseTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'default_severity')
    search_fields = ('name', 'description')
    list_filter = ('organization',)

@admin.register(TaskStatus)
class TaskStatusAdmin(admin.ModelAdmin):
    list_display = ('name', 'color_code')
    search_fields = ('name',)

@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'status', 'organization', 'assignee', 'created_at', 'updated_at')
    search_fields = ('title', 'description')
    list_filter = ('severity', 'status', 'organization', 'created_at')
    date_hierarchy = 'created_at'
    readonly_fields = ('case_id', 'created_at', 'updated_at')

@admin.register(CaseComment)
class CaseCommentAdmin(admin.ModelAdmin):
    list_display = ('comment_id', 'case', 'user', 'created_at')
    search_fields = ('comment_text', 'case__title', 'user__username')
    list_filter = ('created_at', 'user')
    date_hierarchy = 'created_at'
    readonly_fields = ('comment_id', 'created_at')

@admin.register(CaseCustomFieldDefinition)
class CaseCustomFieldDefinitionAdmin(admin.ModelAdmin):
    list_display = ('name', 'technical_name', 'field_type', 'organization', 'is_required', 'is_filterable')
    search_fields = ('name', 'technical_name')
    list_filter = ('field_type', 'is_required', 'is_filterable', 'organization')

@admin.register(CaseCustomFieldValue)
class CaseCustomFieldValueAdmin(admin.ModelAdmin):
    list_display = ('case', 'field_definition')
    search_fields = ('case__title', 'field_definition__name')
    list_filter = ('field_definition',)

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'case', 'status', 'assignee', 'due_date', 'created_at')
    search_fields = ('title', 'description', 'case__title')
    list_filter = ('status', 'assignee', 'due_date', 'created_at')
    date_hierarchy = 'created_at'
    readonly_fields = ('task_id', 'created_at', 'updated_at')

@admin.register(CaseObservable)
class CaseObservableAdmin(admin.ModelAdmin):
    list_display = ('case', 'observable', 'sighted_at')
    search_fields = ('case__title', 'observable__value')
    list_filter = ('sighted_at',)
    date_hierarchy = 'sighted_at'

@admin.register(CaseMitreTechnique)
class CaseMitreTechniqueAdmin(admin.ModelAdmin):
    list_display = ('case', 'technique', 'linked_by', 'linked_at')
    search_fields = ('case__title', 'technique__name', 'technique__technique_id')
    list_filter = ('linked_at',)
    date_hierarchy = 'linked_at' 