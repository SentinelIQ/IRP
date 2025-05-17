from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission
from django.utils.text import slugify


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'
        read_only_fields = ['slug', 'created_at', 'updated_at']
    
    def validate_name(self, value):
        if len(value) < 3:
            raise serializers.ValidationError("O nome da organização deve ter pelo menos 3 caracteres.")
        return value
    
    def create(self, validated_data):
        # Gerar slug automaticamente a partir do nome
        name = validated_data.get('name')
        slug = slugify(name)
        
        # Verificar se o slug já existe e adicionar um número se necessário
        base_slug = slug
        counter = 1
        while Organization.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        validated_data['slug'] = slug
        return super().create(validated_data)


class TeamSerializer(serializers.ModelSerializer):
    organization_id = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        source='organization',
        write_only=True,
        required=False
    )
    organization = OrganizationSerializer(read_only=True)
    members = serializers.PrimaryKeyRelatedField(many=True, queryset=User.objects.all(), required=False)
    member_count = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Team
        fields = ['team_id', 'name', 'description', 'organization', 'organization_id', 
                 'members', 'member_count', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']
    
    def get_member_count(self, obj):
        return obj.members.count()
    
    def validate_name(self, value):
        if len(value) < 2:
            raise serializers.ValidationError("O nome do time deve ter pelo menos 2 caracteres.")
        return value


class ProfileSerializer(serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(source='user', queryset=User.objects.all())
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    organization = OrganizationSerializer(read_only=True)
    organization_id = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        source='organization',
        required=False,
        write_only=True
    )
    teams = serializers.SerializerMethodField(read_only=True)
    roles = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Profile
        fields = ['id', 'user_id', 'username', 'email', 'full_name', 'phone', 'job_title', 
                 'organization', 'organization_id', 'is_system_admin', 'last_login_at', 
                 'created_at', 'updated_at', 'custom_fields', 'teams', 'roles']
        read_only_fields = ['created_at', 'updated_at', 'last_login_at']
    
    def get_teams(self, obj):
        if obj.user:
            return [{'team_id': team.team_id, 'name': team.name} 
                   for team in obj.user.teams.all()]
        return []
    
    def get_roles(self, obj):
        if obj.user:
            user_roles = UserRole.objects.filter(user=obj.user)
            return [{'role_id': ur.role.id, 'name': ur.role.name} 
                   for ur in user_roles]
        return []


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
    password = serializers.CharField(write_only=True, required=False, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, required=False, style={'input_type': 'password'})
    profile = ProfileSerializer(read_only=True)
    organization_id = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        write_only=True,
        required=False
    )
    team_ids = serializers.PrimaryKeyRelatedField(
        queryset=Team.objects.all(),
        write_only=True,
        required=False,
        many=True
    )
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                 'password', 'confirm_password', 'profile', 'organization_id', 'team_ids']
        extra_kwargs = {
            'username': {'required': True},
            'email': {'required': True},
        }
    
    def validate(self, attrs):
        if 'password' in attrs and 'confirm_password' in attrs:
            if attrs['password'] != attrs['confirm_password']:
                raise serializers.ValidationError({"confirm_password": "As senhas não coincidem."})
            attrs.pop('confirm_password')
        return attrs
    
    def create(self, validated_data):
        organization_id = validated_data.pop('organization_id', None)
        team_ids = validated_data.pop('team_ids', None)
        password = validated_data.pop('password', None)
        
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        
        # Criar perfil e associar à organização
        if organization_id:
            Profile.objects.create(user=user, organization=organization_id)
        else:
            Profile.objects.create(user=user)
        
        # Adicionar usuário aos times, se fornecidos
        if team_ids:
            for team in team_ids:
                team.members.add(user)
        
        return user
    
    def update(self, instance, validated_data):
        organization_id = validated_data.pop('organization_id', None)
        team_ids = validated_data.pop('team_ids', None)
        password = validated_data.pop('password', None)
        
        # Atualizar campos básicos do usuário
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        
        if password:
            instance.set_password(password)
        
        instance.save()
        
        # Atualizar organização do perfil, se fornecida
        if organization_id and hasattr(instance, 'profile'):
            instance.profile.organization = organization_id
            instance.profile.save()
        
        # Atualizar times, se fornecidos
        if team_ids is not None:
            instance.teams.clear()
            for team in team_ids:
                team.members.add(instance)
        
        return instance
