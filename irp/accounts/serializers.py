from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'


class TeamSerializer(serializers.ModelSerializer):
    organization = OrganizationSerializer(read_only=True)
    members = serializers.PrimaryKeyRelatedField(many=True, queryset=User.objects.all())
    
    class Meta:
        model = Team
        fields = '__all__'


class ProfileSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    organization = OrganizationSerializer(read_only=True)
    
    class Meta:
        model = Profile
        fields = '__all__'


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = '__all__'


class UserRoleSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    role = RoleSerializer(read_only=True)
    organization = OrganizationSerializer(read_only=True)
    
    class Meta:
        model = UserRole
        fields = '__all__'


class RolePermissionSerializer(serializers.ModelSerializer):
    role = RoleSerializer(read_only=True)
    permission = PermissionSerializer(read_only=True)
    
    class Meta:
        model = RolePermission
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'profile']
