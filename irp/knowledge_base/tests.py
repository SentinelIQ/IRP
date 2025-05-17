from django.test import TestCase
from django.contrib.auth.models import User
from irp.accounts.models import Organization
from .models import KBCategory, KBArticle, KBArticleVersion

class KnowledgeBaseModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.organization = Organization.objects.create(name='Test Org', slug='test-org')
        self.category = KBCategory.objects.create(name='Test Category', organization=self.organization)

    def test_create_kb_category(self):
        self.assertEqual(self.category.name, 'Test Category')
        self.assertEqual(self.category.organization, self.organization)

    def test_create_kb_article(self):
        article = KBArticle.objects.create(
            title='Test Article',
            content='Some content',
            category=self.category,
            organization=self.organization,
            author=self.user
        )
        self.assertEqual(article.title, 'Test Article')
        self.assertEqual(article.category, self.category)
        self.assertEqual(article.organization, self.organization)
        self.assertEqual(article.author, self.user)

    def test_create_kb_article_version(self):
        article = KBArticle.objects.create(
            title='Test Article',
            content='Some content',
            category=self.category,
            organization=self.organization,
            author=self.user
        )
        version = KBArticleVersion.objects.create(
            article=article,
            version_number=1,
            title='Test Article v1',
            content='Version 1 content',
            author=self.user
        )
        self.assertEqual(version.article, article)
        self.assertEqual(version.version_number, 1)
        self.assertEqual(version.title, 'Test Article v1')
        self.assertEqual(version.author, self.user) 