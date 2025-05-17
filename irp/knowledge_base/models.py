from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.text import slugify
from django.db.models import Q
import uuid

class KBCategory(models.Model):
    category_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    parent_category = models.ForeignKey('self', null=True, blank=True, 
                                        related_name='subcategories', 
                                        on_delete=models.CASCADE)
    organization = models.ForeignKey('accounts.Organization', related_name='kb_categories',
                                     null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "KB Categories"

class KBArticle(models.Model):
    STATUS_CHOICES = (
        ('DRAFT', 'Draft'),
        ('PUBLISHED', 'Published'),
        ('ARCHIVED', 'Archived'),
    )
    
    article_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True)
    content = models.TextField()
    category = models.ForeignKey(KBCategory, related_name='articles', 
                                null=True, blank=True, on_delete=models.SET_NULL)
    organization = models.ForeignKey('accounts.Organization', related_name='kb_articles',
                                    null=True, blank=True, on_delete=models.CASCADE)
    author = models.ForeignKey(User, related_name='kb_articles', on_delete=models.SET_NULL, null=True)
    version = models.IntegerField(default=1)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='DRAFT')
    tags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        # Generate slug if not provided
        if not self.slug:
            self.slug = slugify(self.title)
        
        # Set published_at if status changes to PUBLISHED
        if self.status == 'PUBLISHED' and not self.published_at:
            self.published_at = timezone.now()
        
        super().save(*args, **kwargs)

    class Meta:
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['status']),
            models.Index(fields=['organization']),
            models.Index(fields=['category']),
        ]

class KBArticleVersion(models.Model):
    version_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    article = models.ForeignKey(KBArticle, related_name='versions', on_delete=models.CASCADE)
    version_number = models.IntegerField()
    title = models.CharField(max_length=255)
    content = models.TextField()
    author = models.ForeignKey(User, related_name='kb_article_versions', on_delete=models.SET_NULL, null=True)
    changed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('article', 'version_number')
        ordering = ['-version_number'] 