from django.contrib import admin
from .models import KBCategory, KBArticle, KBArticleVersion

@admin.register(KBCategory)
class KBCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'parent_category')
    search_fields = ('name',)
    list_filter = ('organization',)

@admin.register(KBArticle)
class KBArticleAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'organization', 'author', 'status', 'created_at', 'updated_at')
    search_fields = ('title', 'content')
    list_filter = ('status', 'organization', 'category', 'created_at')
    date_hierarchy = 'created_at'
    readonly_fields = ('article_id', 'created_at', 'updated_at')

@admin.register(KBArticleVersion)
class KBArticleVersionAdmin(admin.ModelAdmin):
    list_display = ('article', 'version_number', 'author', 'changed_at')
    search_fields = ('title', 'content', 'article__title')
    list_filter = ('changed_at',)
    date_hierarchy = 'changed_at' 