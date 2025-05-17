from rest_framework import serializers
from django.contrib.auth.models import User
from .models import KBCategory, KBArticle, KBArticleVersion

class KBCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = KBCategory
        fields = '__all__'

class KBArticleVersionSerializer(serializers.ModelSerializer):
    author = serializers.StringRelatedField(read_only=True)
    class Meta:
        model = KBArticleVersion
        fields = '__all__'

class KBArticleSerializer(serializers.ModelSerializer):
    category = KBCategorySerializer(read_only=True)
    author = serializers.StringRelatedField(read_only=True)
    versions = KBArticleVersionSerializer(many=True, read_only=True)
    class Meta:
        model = KBArticle
        fields = '__all__' 