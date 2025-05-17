from django.contrib.auth.models import User
from django.db import transaction
from django.utils.text import slugify

from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission


class OrganizationService:
    @staticmethod
    def create_organization(name, description=None, contact_info=None):
        """
        Create a new organization with a slug based on the name.
        
        Args:
            name (str): The name of the organization
            description (str, optional): Description of the organization
            contact_info (str, optional): Contact information
            
        Returns:
            Organization: The created organization
        """
        slug = slugify(name)
        
        # Check if slug already exists and append a number if needed
        base_slug = slug
        counter = 1
        while Organization.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        return Organization.objects.create(
            name=name,
            description=description or "",
            contact_info=contact_info or "",
            slug=slug
        )
    
    @staticmethod
    def add_user_to_organization(user, organization, is_admin=False):
        """
        Add a user to an organization by creating or updating their profile.
        
        Args:
            user (User): The user to add
            organization (Organization): The organization to add the user to
            is_admin (bool, optional): Whether the user should be an admin of the organization
            
        Returns:
            Profile: The user's profile
        """
        # Get or create profile
        profile, created = Profile.objects.get_or_create(user=user)
        
        # Update profile
        profile.organization = organization
        if is_admin:
            profile.is_system_admin = True
        profile.save()
        
        return profile


class TeamService:
    @staticmethod
    def create_team(name, organization, description=None):
        """
        Create a new team in an organization.
        
        Args:
            name (str): The name of the team
            organization (Organization): The organization the team belongs to
            description (str, optional): Description of the team
            
        Returns:
            Team: The created team
        """
        return Team.objects.create(
            name=name,
            organization=organization,
            description=description or ""
        )
    
    @staticmethod
    def add_user_to_team(user, team):
        """
        Add a user to a team.
        
        Args:
            user (User): The user to add
            team (Team): The team to add the user to
            
        Returns:
            Team: The updated team
        """
        team.members.add(user)
        return team


class RoleService:
    @staticmethod
    @transaction.atomic
    def create_role_with_permissions(name, description=None, permission_codes=None):
        """
        Create a new role with the specified permissions.
        
        Args:
            name (str): The name of the role
            description (str, optional): Description of the role
            permission_codes (list, optional): List of permission codes to assign to the role
            
        Returns:
            Role: The created role
        """
        # Create role
        role = Role.objects.create(
            name=name,
            description=description or ""
        )
        
        # Add permissions if provided
        if permission_codes:
            permissions = Permission.objects.filter(code__in=permission_codes)
            for permission in permissions:
                RolePermission.objects.create(role=role, permission=permission)
        
        return role
    
    @staticmethod
    @transaction.atomic
    def assign_role_to_user(user, role, organization):
        """
        Assign a role to a user in a specific organization.
        
        Args:
            user (User): The user to assign the role to
            role (Role): The role to assign
            organization (Organization): The organization context
            
        Returns:
            UserRole: The created user role assignment
        """
        # Check if the assignment already exists
        user_role, created = UserRole.objects.get_or_create(
            user=user,
            role=role,
            organization=organization
        )
        
        return user_role
