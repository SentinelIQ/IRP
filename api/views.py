from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, permissions, status
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from .models import (
    Organization, Team, Profile, Role, Permission, UserRole, RolePermission,
    AlertSeverity, AlertStatus, Alert, AlertComment, AlertCustomFieldDefinition, AlertCustomFieldValue,
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment, CaseCustomFieldDefinition, CaseCustomFieldValue,
    TaskStatus, Task, ObservableType, TLPLevel, PAPLevel, Observable, CaseObservable, AlertObservable, AuditLog,
    TimelineEvent, MitreTactic, MitreTechnique, CaseMitreTechnique, AlertMitreTechnique, 
    KBCategory, KBArticle, KBArticleVersion,
    NotificationEvent, NotificationChannel, NotificationRule, NotificationLog,
    Metric, MetricSnapshot, Dashboard, DashboardWidget,
    MISPInstance, MISPImport, MISPExport, ReportTemplate, GeneratedReport
)
from .serializers import (
    OrganizationSerializer, TeamSerializer, ProfileSerializer, RoleSerializer, PermissionSerializer,
    UserRoleSerializer, RolePermissionSerializer, UserSerializer,
    AlertSeveritySerializer, AlertStatusSerializer, AlertSerializer, AlertCommentSerializer,
    AlertCustomFieldDefinitionSerializer, AlertCustomFieldValueSerializer,
    CaseSeveritySerializer, CaseStatusSerializer, CaseTemplateSerializer, CaseSerializer, CaseCommentSerializer,
    CaseCustomFieldDefinitionSerializer, CaseCustomFieldValueSerializer,
    TaskStatusSerializer, TaskSerializer, ObservableTypeSerializer, TLPLevelSerializer, PAPLevelSerializer,
    ObservableSerializer, CaseObservableSerializer, AlertObservableSerializer, AuditLogSerializer,
    TimelineEventSerializer, MitreTacticSerializer, MitreTechniqueSerializer,
    CaseMitreTechniqueSerializer, AlertMitreTechniqueSerializer,
    KBCategorySerializer, KBArticleSerializer, KBArticleVersionSerializer,
    NotificationEventSerializer, NotificationChannelSerializer,
    NotificationRuleSerializer, NotificationLogSerializer,
    MetricSerializer, MetricSnapshotSerializer, 
    DashboardSerializer, DashboardWidgetSerializer,
    MISPInstanceSerializer, MISPImportSerializer, MISPExportSerializer, ReportTemplateSerializer, GeneratedReportSerializer,
    TriggerMISPImportSerializer, ExportCaseToMISPSerializer, GenerateReportSerializer
)
from .permissions import HasRolePermission, HasOrganizationPermission
import functools
from django.db.models import Count, Q, F, Avg, Min, Max
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth
from datetime import datetime, timedelta
import json
import requests
from django.utils.text import slugify
from .services import NotificationService, MetricsService
from django.db import models
from django.contrib.auth.models import User
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.contrib.admin.models import LogEntry
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import CHANGE
from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, permissions, status
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from .models import (
    Organization, Team, Profile, Role, Permission, UserRole, RolePermission,
    AlertSeverity, AlertStatus, Alert, AlertComment, AlertCustomFieldDefinition, AlertCustomFieldValue,
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment, CaseCustomFieldDefinition, CaseCustomFieldValue,
    TaskStatus, Task, ObservableType, TLPLevel, PAPLevel, Observable, CaseObservable, AlertObservable, AuditLog,
    TimelineEvent, MitreTactic, MitreTechnique, CaseMitreTechnique, AlertMitreTechnique, 
    KBCategory, KBArticle, KBArticleVersion,
    NotificationEvent, NotificationChannel, NotificationRule, NotificationLog,
    Metric, MetricSnapshot, Dashboard, DashboardWidget
)
from .serializers import (
    OrganizationSerializer, TeamSerializer, ProfileSerializer, RoleSerializer, PermissionSerializer,
    UserRoleSerializer, RolePermissionSerializer, UserSerializer,
    AlertSeveritySerializer, AlertStatusSerializer, AlertSerializer, AlertCommentSerializer,
    AlertCustomFieldDefinitionSerializer, AlertCustomFieldValueSerializer,
    CaseSeveritySerializer, CaseStatusSerializer, CaseTemplateSerializer, CaseSerializer, CaseCommentSerializer,
    CaseCustomFieldDefinitionSerializer, CaseCustomFieldValueSerializer,
    TaskStatusSerializer, TaskSerializer, ObservableTypeSerializer, TLPLevelSerializer, PAPLevelSerializer,
    ObservableSerializer, CaseObservableSerializer, AlertObservableSerializer, AuditLogSerializer,
    TimelineEventSerializer, MitreTacticSerializer, MitreTechniqueSerializer,
    CaseMitreTechniqueSerializer, AlertMitreTechniqueSerializer,
    KBCategorySerializer, KBArticleSerializer, KBArticleVersionSerializer,
    NotificationEventSerializer, NotificationChannelSerializer,
    NotificationRuleSerializer, NotificationLogSerializer,
    MetricSerializer, MetricSnapshotSerializer, 
    DashboardSerializer, DashboardWidgetSerializer
)
from .permissions import HasRolePermission
import functools
from django.db.models import Count, Q, F, Avg, Min, Max
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth
from datetime import datetime, timedelta
import json
import requests
from django.utils.text import slugify
from .services import NotificationService, MetricsService

# Decorator para auditoria de ações
def audit_action(entity_type, action_type, get_entity_id_func=None):
    """
    Decorator para registrar ações no log de auditoria.
    
    Args:
        entity_type (str): Tipo da entidade (ALERT, CASE, TASK, etc)
        action_type (str): Tipo da ação (CREATE, UPDATE, DELETE, etc)
        get_entity_id_func (callable, optional): Função para extrair o ID da entidade do resultado.
            Se não fornecido, tenta obter o ID do objeto retornado.
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            # Salvar estado antes da operação para comparação posterior
            details_before = None
            entity_id = None
            
            # Executar a view original
            result = view_func(self, request, *args, **kwargs)
            
            # Extrair ID da entidade
            if get_entity_id_func:
                entity_id = get_entity_id_func(result, self, request, *args, **kwargs)
            elif hasattr(self, 'get_object') and entity_type in ['ALERT', 'CASE', 'TASK', 'OBSERVABLE']:
                # Para ViewSets padrão, tenta obter o ID do objeto atual
                try:
                    obj = self.get_object()
                    entity_id = getattr(obj, f"{entity_type.lower()}_id", None)
                except:
                    pass
            
            # Se não conseguiu obter o ID ainda e a resposta tem dados, tenta extrair daí
            if not entity_id and hasattr(result, 'data') and isinstance(result.data, dict):
                id_key = f"{entity_type.lower()}_id"
                entity_id = result.data.get(id_key)
            
            # Registrar na auditoria apenas se conseguiu identificar a entidade
            if entity_id:
                # Obter organização do usuário
                user = request.user
                organization = None
                if hasattr(user, 'profile') and user.profile.organization:
                    organization = user.profile.organization
                
                # Dados após a operação
                details_after = None
                if hasattr(result, 'data'):
                    details_after = result.data
                
                # Criar entrada de auditoria
                if organization:
                    AuditLog.objects.create(
                        user=user,
                        organization=organization,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        action_type=action_type,
                        details_before=details_before,
                        details_after=details_after
                    )
            
            return result
        return wrapper
    return decorator

# Create your views here.

class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_organizations'

class TeamViewSet(viewsets.ModelViewSet):
    queryset = Team.objects.all()
    serializer_class = TeamSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_teams'

    def get_queryset(self):
        # Isolamento multi-tenant: só times da organização do usuário
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return Team.objects.filter(organization=user.profile.organization)
        return Team.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_roles'

class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_permissions'

class UserRoleViewSet(viewsets.ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'assign_roles'

class RolePermissionViewSet(viewsets.ModelViewSet):
    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'assign_permissions'

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = serializer.save()
        # Cria perfil automaticamente
        Profile.objects.create(user=user)

    def get_queryset(self):
        # Usuário só vê a si mesmo ou membros da sua organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org = user.profile.organization
            return User.objects.filter(profile__organization=org)
        return User.objects.filter(id=user.id)

# Etapa 2 - Alert Management Views

class AlertSeverityViewSet(viewsets.ModelViewSet):
    queryset = AlertSeverity.objects.all()
    serializer_class = AlertSeveritySerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_alert_settings'

class AlertStatusViewSet(viewsets.ModelViewSet):
    queryset = AlertStatus.objects.all()
    serializer_class = AlertStatusSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_alert_settings'
    
    def get_queryset(self):
        # Retorna status globais (organization=None) ou específicos da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return AlertStatus.objects.filter(organization__isnull=True) | AlertStatus.objects.filter(organization_id=org_id)
        return AlertStatus.objects.filter(organization__isnull=True)
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'alert:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'alert:edit'
        elif self.action == 'destroy':
            self.required_permission = 'alert:delete'
        elif self.action == 'escalate_to_case':
            self.required_permission = 'alert:escalate'
        return super().get_permissions()
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return Alert.objects.filter(organization_id=org_id, is_deleted=False)
        return Alert.objects.none()
    
    @audit_action(entity_type='ALERT', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        
        if not hasattr(user, 'profile') or not user.profile.organization:
            raise PermissionError("Usuário não possui organização")
        
        # Obter os valores necessários dos parâmetros
        severity_id = self.request.data.get('severity_id')
        status_id = self.request.data.get('status_id')
        
        # Verificar se há um status padrão, caso nenhum tenha sido fornecido
        if not status_id:
            default_status = AlertStatus.objects.filter(
                organization=user.profile.organization,
                is_default_open_status=True
            ).first() or AlertStatus.objects.filter(
                organization__isnull=True,
                is_default_open_status=True
            ).first()
            
            if default_status:
                status_id = default_status.id
        
        # Buscar os objetos relacionados
        severity = get_object_or_404(AlertSeverity, pk=severity_id) if severity_id else None
        status = get_object_or_404(AlertStatus, pk=status_id) if status_id else None
        
        return serializer.save(
            organization=user.profile.organization,
            severity=severity,
            status=status,
            first_seen_at=timezone.now()
        )
    
    @audit_action(entity_type='ALERT', action_type='UPDATE')
    def perform_update(self, serializer):
        alert = self.get_object()
        
        # Capturar estado anterior para auditoria
        previous_status = alert.status
        
        # Realizar a atualização normal
        serializer.save()
        
        # Se status mudou, registrar também como mudança de status
        if 'status' in serializer.validated_data and previous_status != alert.status:
            AuditLog.objects.create(
                user=self.request.user,
                organization=alert.organization,
                entity_type='ALERT',
                entity_id=alert.alert_id,
                action_type='STATUS_CHANGE',
                details_before={'status': str(previous_status)},
                details_after={'status': str(alert.status)}
            )
    
    @audit_action(entity_type='ALERT', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        alert = self.get_object()
        # Soft delete
        alert.is_deleted = True
        alert.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @audit_action(entity_type='ALERT', action_type='ESCALATE')
    def escalate_to_case(self, request, pk=None):
        alert = self.get_object()
        
        # Obter parâmetros para o novo caso
        title = request.data.get('title', alert.title)
        template_id = request.data.get('template_id')
        severity_id = request.data.get('severity_id')
        description = request.data.get('description', alert.description)
        
        # Verificar se há um status padrão para casos
        default_case_status = CaseStatus.objects.filter(
            organization=alert.organization,
            is_default_open_status=True
        ).first() or CaseStatus.objects.filter(
            organization__isnull=True,
            is_default_open_status=True
        ).first()
        
        if not default_case_status:
            return Response(
                {"detail": "Não foi possível encontrar um status padrão para casos."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Buscar severidade (usar a mesma do alerta se não especificada)
        if not severity_id:
            # Mapeamento aproximado entre severidades de alerta e caso
            alert_severity_name = alert.severity.name
            case_severity = CaseSeverity.objects.filter(name=alert_severity_name).first()
        else:
            case_severity = get_object_or_404(CaseSeverity, pk=severity_id)
        
        # Buscar template se especificado
        template = None
        if template_id:
            template = get_object_or_404(CaseTemplate, pk=template_id)
        
        # Criar o caso
        case = Case.objects.create(
            title=title,
            description=description,
            severity=case_severity,
            status=default_case_status,
            organization=alert.organization,
            reporter=request.user,
            template=template
        )
        
        # Associar o alerta ao caso
        case.alerts.add(alert)
        
        # Atualizar status do alerta para indicar que foi escalado
        escalated_status = AlertStatus.objects.filter(
            organization=alert.organization,
            name__icontains='Escalated'
        ).first() or AlertStatus.objects.filter(
            organization__isnull=True,
            name__icontains='Escalated'
        ).first()
        
        if escalated_status:
            alert.status = escalated_status
            alert.save()
        
        # Se há um template, processar as tarefas predefinidas
        if template and template.predefined_tasks:
            task_status_todo = TaskStatus.objects.filter(name='ToDo').first()
            
            for task_def in template.predefined_tasks:
                Task.objects.create(
                    case=case,
                    title=task_def.get('title', ''),
                    description=task_def.get('description', ''),
                    status=task_status_todo,
                    order=task_def.get('order', 0)
                )
        
        # Registrar na auditoria
        AuditLog.objects.create(
            user=request.user,
            organization=alert.organization,
            entity_type='ALERT',
            entity_id=alert.alert_id,
            action_type='STATUS_CHANGE',
            details_before={'status': str(alert.status)},
            details_after={'status': str(escalated_status) if escalated_status else None, 'escalated_to_case': str(case.case_id)}
        )
        
        # Retornar detalhes do caso criado
        serializer = CaseSerializer(case)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['get'])
    def similar(self, request, pk=None):
        """
        Encontra alertas similares com base no título, descrição e observáveis em comum.
        Retorna uma lista de alertas ordenada por score de similaridade.
        """
        alert = self.get_object()
        organization_id = alert.organization.organization_id
        
        # Busca por título similar (exato ou parcial)
        title_matches = Alert.objects.filter(
            organization_id=organization_id,
            title__icontains=alert.title,
            is_deleted=False
        ).exclude(alert_id=alert.alert_id)
        
        # Busca por mesma fonte e ID externo
        source_matches = Alert.objects.filter(
            organization_id=organization_id,
            source_system=alert.source_system,
            external_alert_id=alert.external_alert_id,
            is_deleted=False
        ).exclude(alert_id=alert.alert_id)
        
        # Busca por observáveis em comum
        observable_ids = [ao.observable.observable_id for ao in alert.alert_observables.all()]
        if observable_ids:
            alerts_with_same_observables = AlertObservable.objects.filter(
                observable__observable_id__in=observable_ids,
                alert__organization_id=organization_id,
                alert__is_deleted=False
            ).exclude(alert__alert_id=alert.alert_id).values_list('alert__alert_id', flat=True)
            
            observable_matches = Alert.objects.filter(alert_id__in=alerts_with_same_observables)
        else:
            observable_matches = Alert.objects.none()
        
        # Combinar resultados e calcular scores
        similar_alerts = {}
        
        # Pontuação alta para alertas com a mesma origem e ID
        for a in source_matches:
            if a.alert_id not in similar_alerts:
                similar_alerts[a.alert_id] = {
                    'alert': a,
                    'score': 100,
                    'match_reason': 'Mesma fonte e ID externo'
                }
        
        # Pontuação média para títulos similares
        for a in title_matches:
            if a.alert_id not in similar_alerts:
                similar_alerts[a.alert_id] = {
                    'alert': a,
                    'score': 50,
                    'match_reason': 'Título similar'
                }
            else:
                similar_alerts[a.alert_id]['score'] += 30
                similar_alerts[a.alert_id]['match_reason'] += ', Título similar'
        
        # Pontuação baseada em observáveis comuns
        for a in observable_matches:
            if a.alert_id not in similar_alerts:
                similar_alerts[a.alert_id] = {
                    'alert': a,
                    'score': 40,
                    'match_reason': 'Observáveis em comum'
                }
            else:
                similar_alerts[a.alert_id]['score'] += 20
                similar_alerts[a.alert_id]['match_reason'] += ', Observáveis em comum'
        
        # Ordenar resultados por score
        results = sorted(similar_alerts.values(), key=lambda x: x['score'], reverse=True)
        
        # Serializar e retornar resultados
        serialized_results = []
        for item in results:
            alert_data = AlertSerializer(item['alert'], context={'request': request}).data
            serialized_results.append({
                'alert': alert_data,
                'similarity_score': item['score'],
                'match_reason': item['match_reason']
            })
        
        return Response(serialized_results)

class AlertCommentViewSet(viewsets.ModelViewSet):
    queryset = AlertComment.objects.all()
    serializer_class = AlertCommentSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:comment'
    
    def get_queryset(self):
        alert_id = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if alert_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return AlertComment.objects.filter(alert__alert_id=alert_id, alert__organization_id=org_id)
        return AlertComment.objects.none()
    
    @audit_action(entity_type='ALERT_COMMENT', action_type='CREATE')
    def perform_create(self, serializer):
        alert_id = self.kwargs.get('alert_pk')
        alert = get_object_or_404(Alert, alert_id=alert_id)
        
        # Verificar se o usuário pertence à mesma organização do alerta
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == alert.organization:
            serializer.save(alert=alert, user=user)
        else:
            raise PermissionError("Usuário não pode comentar neste alerta")

    @audit_action(entity_type='ALERT_COMMENT', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='ALERT_COMMENT', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

# Etapa 2 - Case Management Views

class CaseSeverityViewSet(viewsets.ModelViewSet):
    queryset = CaseSeverity.objects.all()
    serializer_class = CaseSeveritySerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

class CaseStatusViewSet(viewsets.ModelViewSet):
    queryset = CaseStatus.objects.all()
    serializer_class = CaseStatusSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'
    
    def get_queryset(self):
        # Retorna status globais (organization=None) ou específicos da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return CaseStatus.objects.filter(organization__isnull=True) | CaseStatus.objects.filter(organization_id=org_id)
        return CaseStatus.objects.filter(organization__isnull=True)
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class CaseTemplateViewSet(viewsets.ModelViewSet):
    queryset = CaseTemplate.objects.all()
    serializer_class = CaseTemplateSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_templates'
    
    def get_queryset(self):
        # Retorna templates globais (organization=None) ou específicos da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return CaseTemplate.objects.filter(organization__isnull=True) | CaseTemplate.objects.filter(organization_id=org_id)
        return CaseTemplate.objects.filter(organization__isnull=True)
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class CaseViewSet(viewsets.ModelViewSet):
    queryset = Case.objects.all()
    serializer_class = CaseSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'case:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'case:edit'
        elif self.action == 'destroy':
            self.required_permission = 'case:delete'
        elif self.action == 'related':
            self.required_permission = 'case:view'
        return super().get_permissions()
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return Case.objects.filter(organization_id=org_id)
        return Case.objects.none()
    
    @audit_action(entity_type='CASE', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        
        if not hasattr(user, 'profile') or not user.profile.organization:
            raise PermissionError("Usuário não possui organização")
        
        # Obter os valores necessários dos parâmetros
        severity_id = self.request.data.get('severity_id')
        status_id = self.request.data.get('status_id')
        template_id = self.request.data.get('template_id')
        
        # Verificar se há um status padrão, caso nenhum tenha sido fornecido
        if not status_id:
            default_status = CaseStatus.objects.filter(
                organization=user.profile.organization,
                is_default_open_status=True
            ).first() or CaseStatus.objects.filter(
                organization__isnull=True,
                is_default_open_status=True
            ).first()
            
            if default_status:
                status_id = default_status.id
        
        # Buscar os objetos relacionados
        severity = get_object_or_404(CaseSeverity, pk=severity_id) if severity_id else None
        status = get_object_or_404(CaseStatus, pk=status_id) if status_id else None
        template = get_object_or_404(CaseTemplate, pk=template_id) if template_id else None
        
        # Criar o caso
        case = serializer.save(
            organization=user.profile.organization,
            severity=severity,
            status=status,
            template=template,
            reporter=user
        )
        
        # Adicionar evento na timeline
        create_timeline_event(
            case=case,
            organization=user.profile.organization,
            event_type='CASE_CREATED',
            description=f"Caso criado por {user.get_full_name() or user.username}",
            actor=user,
            metadata={
                'title': case.title,
                'severity': str(severity) if severity else None,
                'status': str(status) if status else None,
                'template': str(template) if template else None
            }
        )
        
        # Se há um template, processar as tarefas predefinidas
        if template and template.predefined_tasks:
            task_status_todo = TaskStatus.objects.filter(name='ToDo').first()
            
            for task_def in template.predefined_tasks:
                task = Task.objects.create(
                    case=case,
                    title=task_def.get('title', ''),
                    description=task_def.get('description', ''),
                    status=task_status_todo,
                    order=task_def.get('order', 0)
                )
                
                # Adicionar evento na timeline para cada tarefa criada
                create_timeline_event(
                    case=case,
                    organization=user.profile.organization,
                    event_type='TASK_CREATED',
                    description=f"Tarefa '{task.title}' criada automaticamente do template",
                    actor=user,
                    target_entity_type='Task',
                    target_entity_id=str(task.task_id)
                )
        
        return case

    @audit_action(entity_type='CASE', action_type='UPDATE')
    def perform_update(self, serializer):
        case = self.get_object()
        user = self.request.user
        
        # Capturar estado anterior para auditoria
        previous_status = case.status
        previous_assignee = case.assignee
        
        # Realizar a atualização normal
        serializer.save()
        
        # Se status mudou, registrar também como mudança de status
        if 'status' in serializer.validated_data and previous_status != case.status:
            # Se o status é terminal, registrar data de fechamento
            if case.status.is_terminal_status and not case.closed_at:
                case.closed_at = timezone.now()
                case.save(update_fields=['closed_at'])
            
            AuditLog.objects.create(
                user=self.request.user,
                organization=case.organization,
                entity_type='CASE',
                entity_id=case.case_id,
                action_type='STATUS_CHANGE',
                details_before={'status': str(previous_status)},
                details_after={'status': str(case.status)}
            )
            
            # Adicionar evento na timeline
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='STATUS_CHANGED',
                description=f"Status alterado de '{previous_status}' para '{case.status}'",
                actor=user,
                metadata={
                    'old_status': str(previous_status),
                    'new_status': str(case.status)
                }
            )
        
        # Se assignee mudou, registrar também como atribuição
        if 'assignee' in serializer.validated_data and previous_assignee != case.assignee:
            AuditLog.objects.create(
                user=self.request.user,
                organization=case.organization,
                entity_type='CASE',
                entity_id=case.case_id,
                action_type='ASSIGN',
                details_before={'assignee': str(previous_assignee) if previous_assignee else None},
                details_after={'assignee': str(case.assignee) if case.assignee else None}
            )
            
            # Adicionar evento na timeline
            if case.assignee:
                description = f"Caso atribuído para {case.assignee.get_full_name() or case.assignee.username}"
            else:
                description = "Atribuição do caso removida"
                
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='USER_ASSIGNED',
                description=description,
                actor=user,
                metadata={
                    'old_assignee': str(previous_assignee) if previous_assignee else None,
                    'new_assignee': str(case.assignee) if case.assignee else None
                }
            )
    
    @audit_action(entity_type='CASE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['get'])
    def related(self, request, pk=None):
        """
        Encontra casos relacionados com base em observáveis comuns, alertas compartilhados,
        ou outros critérios de similaridade.
        """
        case = self.get_object()
        organization_id = case.organization.organization_id
        
        # Buscar casos com alertas em comum
        alert_ids = case.alerts.values_list('alert_id', flat=True)
        cases_with_same_alerts = Case.objects.filter(
            organization_id=organization_id,
            alerts__alert_id__in=alert_ids
        ).exclude(case_id=case.case_id).distinct()
        
        # Buscar casos com observáveis em comum
        observable_ids = [co.observable.observable_id for co in case.case_observables.all()]
        cases_with_same_observables = CaseObservable.objects.filter(
            observable__observable_id__in=observable_ids,
            case__organization_id=organization_id
        ).exclude(case__case_id=case.case_id).values_list('case__case_id', flat=True)
        
        cases_with_same_observables_qs = Case.objects.filter(case_id__in=cases_with_same_observables)
        
        # Combinar resultados e calcular scores
        related_cases = {}
        
        # Pontuação alta para casos com os mesmos alertas
        for c in cases_with_same_alerts:
            if c.case_id not in related_cases:
                related_cases[c.case_id] = {
                    'case': c,
                    'score': 80,
                    'relation_reason': 'Alertas em comum'
                }
        
        # Pontuação baseada em observáveis comuns
        for c in cases_with_same_observables_qs:
            if c.case_id not in related_cases:
                related_cases[c.case_id] = {
                    'case': c,
                    'score': 60,
                    'relation_reason': 'Observáveis em comum'
                }
            else:
                related_cases[c.case_id]['score'] += 30
                related_cases[c.case_id]['relation_reason'] += ', Observáveis em comum'
        
        # Ordenar resultados por score
        results = sorted(related_cases.values(), key=lambda x: x['score'], reverse=True)
        
        # Serializar e retornar resultados
        serialized_results = []
        for item in results:
            case_data = CaseSerializer(item['case'], context={'request': request}).data
            serialized_results.append({
                'case': case_data,
                'relation_score': item['score'],
                'relation_reason': item['relation_reason']
            })
        
        return Response(serialized_results)

class TaskStatusViewSet(viewsets.ModelViewSet):
    queryset = TaskStatus.objects.all()
    serializer_class = TaskStatusSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'task:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'task:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'task:edit'
        elif self.action == 'destroy':
            self.required_permission = 'task:delete'
        return super().get_permissions()
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return Task.objects.filter(case__case_id=case_id, case__organization_id=org_id)
        return Task.objects.none()
    
    @audit_action(entity_type='TASK', action_type='CREATE')
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        user = self.request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            status_id = self.request.data.get('status_id')
            status = get_object_or_404(TaskStatus, pk=status_id) if status_id else TaskStatus.objects.filter(name='ToDo').first()
            
            task = serializer.save(case=case, status=status)
            
            # Adicionar evento na timeline
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='TASK_CREATED',
                description=f"Tarefa '{task.title}' criada por {user.get_full_name() or user.username}",
                actor=user,
                target_entity_type='Task',
                target_entity_id=str(task.task_id),
                metadata={
                    'task_title': task.title,
                    'task_description': task.description,
                    'task_status': str(task.status)
                }
            )
            
            return task
        else:
            raise PermissionError("Usuário não pode criar tarefas neste caso")

    @audit_action(entity_type='TASK', action_type='UPDATE')
    def perform_update(self, serializer):
        task = self.get_object()
        user = self.request.user
        
        # Capturar estado anterior para auditoria
        previous_status = task.status
        previous_assignee = task.assignee
        
        # Realizar a atualização normal
        serializer.save()
        
        # Se status mudou, registrar também como mudança de status
        if 'status' in serializer.validated_data and previous_status != task.status:
            AuditLog.objects.create(
                user=user,
                organization=task.case.organization,
                entity_type='TASK',
                entity_id=task.task_id,
                action_type='STATUS_CHANGE',
                details_before={'status': str(previous_status)},
                details_after={'status': str(task.status)}
            )
            
            # Adicionar evento na timeline
            event_type = 'TASK_STATUS_CHANGED'
            description = f"Status da tarefa '{task.title}' alterado de '{previous_status}' para '{task.status}'"
            
            # Se o status novo for completo/fechado, usar um evento de tarefa concluída
            if task.status.name.lower() in ['done', 'completed', 'finished', 'closed']:
                event_type = 'TASK_COMPLETED'
                description = f"Tarefa '{task.title}' concluída por {user.get_full_name() or user.username}"
            
            create_timeline_event(
                case=task.case,
                organization=task.case.organization,
                event_type=event_type,
                description=description,
                actor=user,
                target_entity_type='Task',
                target_entity_id=str(task.task_id),
                metadata={
                    'task_title': task.title,
                    'old_status': str(previous_status),
                    'new_status': str(task.status)
                }
            )
        
        # Se assignee mudou, registrar também como atribuição
        if 'assignee' in serializer.validated_data and previous_assignee != task.assignee:
            AuditLog.objects.create(
                user=user,
                organization=task.case.organization,
                entity_type='TASK',
                entity_id=task.task_id,
                action_type='ASSIGN',
                details_before={'assignee': str(previous_assignee) if previous_assignee else None},
                details_after={'assignee': str(task.assignee) if task.assignee else None}
            )
            
            # Adicionar evento na timeline
            if task.assignee:
                description = f"Tarefa '{task.title}' atribuída para {task.assignee.get_full_name() or task.assignee.username}"
            else:
                description = f"Atribuição da tarefa '{task.title}' removida"
                
            create_timeline_event(
                case=task.case,
                organization=task.case.organization,
                event_type='TASK_ASSIGNED',
                description=description,
                actor=user,
                target_entity_type='Task',
                target_entity_id=str(task.task_id),
                metadata={
                    'task_title': task.title,
                    'old_assignee': str(previous_assignee.id) if previous_assignee else None,
                    'new_assignee': str(task.assignee.id) if task.assignee else None
                }
            )
    
    @audit_action(entity_type='TASK', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        task = self.get_object()
        user = request.user
        
        # Adicionar evento na timeline antes de excluir
        create_timeline_event(
            case=task.case,
            organization=task.case.organization,
            event_type='TASK_DELETED',
            description=f"Tarefa '{task.title}' removida por {user.get_full_name() or user.username}",
            actor=user,
            target_entity_type='Task',
            target_entity_id=str(task.task_id),
            metadata={
                'task_title': task.title,
                'task_status': str(task.status)
            }
        )
        
        return super().destroy(request, *args, **kwargs)

class CaseCommentViewSet(viewsets.ModelViewSet):
    queryset = CaseComment.objects.all()
    serializer_class = CaseCommentSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:comment'
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return CaseComment.objects.filter(case__case_id=case_id, case__organization_id=org_id)
        return CaseComment.objects.none()
    
    @audit_action(entity_type='CASE_COMMENT', action_type='CREATE')
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        user = self.request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            comment = serializer.save(case=case, user=user)
            
            # Adicionar evento na timeline
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='COMMENT_ADDED',
                description=f"Comentário adicionado por {user.get_full_name() or user.username}",
                actor=user,
                target_entity_type='Comment',
                target_entity_id=str(comment.id),
                metadata={
                    'comment_text': comment.text[:100] + ('...' if len(comment.text) > 100 else '')
                }
            )
            
            return comment
        else:
            raise PermissionError("Usuário não pode comentar neste caso")

    @audit_action(entity_type='CASE_COMMENT', action_type='UPDATE')
    def perform_update(self, serializer):
        comment = self.get_object()
        user = self.request.user
        case = comment.case
        
        # Verificar se é o autor do comentário ou tem permissão especial
        if comment.user != user and not user.has_perm('case:edit_any_comment'):
            raise PermissionError("Usuário não pode editar este comentário")
        
        updated_comment = serializer.save()
        
        # Adicionar evento na timeline
        create_timeline_event(
            case=case,
            organization=case.organization,
            event_type='COMMENT_UPDATED',
            description=f"Comentário editado por {user.get_full_name() or user.username}",
            actor=user,
            target_entity_type='Comment',
            target_entity_id=str(comment.id),
            metadata={
                'comment_text': updated_comment.text[:100] + ('...' if len(updated_comment.text) > 100 else '')
            }
        )
        
        return updated_comment
    
    @audit_action(entity_type='CASE_COMMENT', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        comment = self.get_object()
        user = request.user
        case = comment.case
        
        # Verificar se é o autor do comentário ou tem permissão especial
        if comment.user != user and not user.has_perm('case:delete_any_comment'):
            raise PermissionError("Usuário não pode excluir este comentário")
        
        # Adicionar evento na timeline
        create_timeline_event(
            case=case,
            organization=case.organization,
            event_type='COMMENT_DELETED',
            description=f"Comentário excluído por {user.get_full_name() or user.username}",
            actor=user,
            target_entity_type='Comment',
            target_entity_id=str(comment.id),
            metadata={
                'comment_text': comment.text[:100] + ('...' if len(comment.text) > 100 else '')
            }
        )
        
        return super().destroy(request, *args, **kwargs)

# Observables Management Views

class ObservableTypeViewSet(viewsets.ModelViewSet):
    queryset = ObservableType.objects.all()
    serializer_class = ObservableTypeSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

class TLPLevelViewSet(viewsets.ModelViewSet):
    queryset = TLPLevel.objects.all()
    serializer_class = TLPLevelSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

class PAPLevelViewSet(viewsets.ModelViewSet):
    queryset = PAPLevel.objects.all()
    serializer_class = PAPLevelSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

class AlertCustomFieldDefinitionViewSet(viewsets.ModelViewSet):
    queryset = AlertCustomFieldDefinition.objects.all()
    serializer_class = AlertCustomFieldDefinitionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_alert_settings'
    
    def get_queryset(self):
        # Retorna definições globais (organization=None) ou específicas da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return AlertCustomFieldDefinition.objects.filter(organization__isnull=True) | AlertCustomFieldDefinition.objects.filter(organization_id=org_id)
        return AlertCustomFieldDefinition.objects.filter(organization__isnull=True)
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_DEF', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_DEF', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_DEF', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

class AlertCustomFieldValueViewSet(viewsets.ModelViewSet):
    queryset = AlertCustomFieldValue.objects.all()
    serializer_class = AlertCustomFieldValueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:edit'
    
    def get_queryset(self):
        alert_id = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if alert_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return AlertCustomFieldValue.objects.filter(alert__alert_id=alert_id, alert__organization_id=org_id)
        return AlertCustomFieldValue.objects.none()
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_VALUE', action_type='CREATE')
    def perform_create(self, serializer):
        alert_id = self.kwargs.get('alert_pk')
        alert = get_object_or_404(Alert, alert_id=alert_id)
        
        # Verificar se o usuário pertence à mesma organização do alerta
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == alert.organization:
            field_definition_id = self.request.data.get('field_definition_id')
            field_definition = get_object_or_404(AlertCustomFieldDefinition, pk=field_definition_id)
            
            serializer.save(
                alert=alert,
                field_definition=field_definition
            )
        else:
            raise PermissionError("Usuário não pode adicionar campos customizados a este alerta")
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_VALUE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_VALUE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

class CaseCustomFieldDefinitionViewSet(viewsets.ModelViewSet):
    queryset = CaseCustomFieldDefinition.objects.all()
    serializer_class = CaseCustomFieldDefinitionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'
    
    def get_queryset(self):
        # Retorna definições globais (organization=None) ou específicas da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return CaseCustomFieldDefinition.objects.filter(organization__isnull=True) | CaseCustomFieldDefinition.objects.filter(organization_id=org_id)
        return CaseCustomFieldDefinition.objects.filter(organization__isnull=True)
    
    @audit_action(entity_type='CASE_CUSTOM_FIELD_DEF', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()
    
    @audit_action(entity_type='CASE_CUSTOM_FIELD_DEF', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='CASE_CUSTOM_FIELD_DEF', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

class CaseCustomFieldValueViewSet(viewsets.ModelViewSet):
    queryset = CaseCustomFieldValue.objects.all()
    serializer_class = CaseCustomFieldValueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:edit'
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return CaseCustomFieldValue.objects.filter(case__case_id=case_id, case__organization_id=org_id)
        return CaseCustomFieldValue.objects.none()
    
    @audit_action(entity_type='CASE_CUSTOM_FIELD_VALUE', action_type='CREATE')
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        
        # Verificar se o usuário pertence à mesma organização do caso
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            field_definition_id = self.request.data.get('field_definition_id')
            field_definition = get_object_or_404(CaseCustomFieldDefinition, pk=field_definition_id)
            
            serializer.save(
                case=case,
                field_definition=field_definition
            )
        else:
            raise PermissionError("Usuário não pode adicionar campos customizados a este caso")
    
    @audit_action(entity_type='CASE_CUSTOM_FIELD_VALUE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='CASE_CUSTOM_FIELD_VALUE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def dashboard_stats(request):
    """Endpoint para fornecer estatísticas para o dashboard"""
    
    # Verificar permissão
    if not request.user.has_perm('view_dashboard'):
        return Response({"error": "Sem permissão para acessar o dashboard"}, status=status.HTTP_403_FORBIDDEN)
    
    # Obter organização do usuário
    user = request.user
    if not hasattr(user, 'profile') or not user.profile.organization:
        return Response({"error": "Usuário sem organização"}, status=status.HTTP_400_BAD_REQUEST)
    
    organization = user.profile.organization
    
    # Período para estatísticas (padrão: últimos 30 dias)
    days = int(request.query_params.get('days', 30))
    date_from = timezone.now() - timedelta(days=days)
    
    # Alertas por severidade
    alerts_by_severity = Alert.objects.filter(
        organization=organization,
        created_at__gte=date_from,
        is_deleted=False
    ).values('severity__name').annotate(count=Count('alert_id')).order_by('-count')
    
    # Casos por severidade
    cases_by_severity = Case.objects.filter(
        organization=organization,
        created_at__gte=date_from
    ).values('severity__name').annotate(count=Count('case_id')).order_by('-count')
    
    # Alertas por status
    alerts_by_status = Alert.objects.filter(
        organization=organization,
        created_at__gte=date_from,
        is_deleted=False
    ).values('status__name').annotate(count=Count('alert_id')).order_by('-count')
    
    # Casos por status
    cases_by_status = Case.objects.filter(
        organization=organization,
        created_at__gte=date_from
    ).values('status__name').annotate(count=Count('case_id')).order_by('-count')
    
    # Tendência de alertas por dia
    alert_trends = Alert.objects.filter(
        organization=organization,
        created_at__gte=date_from,
        is_deleted=False
    ).annotate(
        date=TruncDay('created_at')
    ).values('date').annotate(
        count=Count('alert_id')
    ).order_by('date')
    
    # Tempo médio de resolução de casos (casos fechados)
    avg_case_resolution = Case.objects.filter(
        organization=organization,
        created_at__gte=date_from,
        closed_at__isnull=False
    ).annotate(
        resolution_time=F('closed_at') - F('created_at')
    ).aggregate(
        avg_time=Avg('resolution_time')
    )
    
    # Estatísticas gerais
    stats = {
        'total_alerts': Alert.objects.filter(
            organization=organization,
            is_deleted=False
        ).count(),
        'total_cases': Case.objects.filter(
            organization=organization
        ).count(),
        'open_alerts': Alert.objects.filter(
            organization=organization,
            status__is_terminal_status=False,
            is_deleted=False
        ).count(),
        'open_cases': Case.objects.filter(
            organization=organization,
            status__is_terminal_status=False
        ).count(),
        'new_alerts_today': Alert.objects.filter(
            organization=organization,
            created_at__gte=timezone.now().replace(hour=0, minute=0, second=0),
            is_deleted=False
        ).count(),
        'closed_cases_today': Case.objects.filter(
            organization=organization,
            closed_at__gte=timezone.now().replace(hour=0, minute=0, second=0)
        ).count(),
    }
    
    return Response({
        'alerts_by_severity': alerts_by_severity,
        'cases_by_severity': cases_by_severity,
        'alerts_by_status': alerts_by_status,
        'cases_by_status': cases_by_status,
        'alert_trends': alert_trends,
        'avg_case_resolution': avg_case_resolution,
        'stats': stats,
        'period_days': days
    })

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def reports(request, report_type=None):
    """Endpoint para gerar relatórios"""
    
    # Verificar permissão
    if not request.user.has_perm('generate_reports'):
        return Response({"error": "Sem permissão para gerar relatórios"}, status=status.HTTP_403_FORBIDDEN)
    
    # Obter organização do usuário
    user = request.user
    if not hasattr(user, 'profile') or not user.profile.organization:
        return Response({"error": "Usuário sem organização"}, status=status.HTTP_400_BAD_REQUEST)
    
    organization = user.profile.organization
    
    # Período para o relatório
    days = int(request.query_params.get('days', 30))
    date_from = timezone.now() - timedelta(days=days)
    
    if report_type == 'alerts':
        # Relatório de alertas
        alerts = Alert.objects.filter(
            organization=organization,
            created_at__gte=date_from,
            is_deleted=False
        )
        
        data = {
            'total_alerts': alerts.count(),
            'alerts_by_severity': alerts.values('severity__name').annotate(count=Count('alert_id')),
            'alerts_by_status': alerts.values('status__name').annotate(count=Count('alert_id')),
            'alerts_by_source': alerts.values('source_system').annotate(count=Count('alert_id')),
            'alerts_by_day': alerts.annotate(
                day=TruncDay('created_at')
            ).values('day').annotate(count=Count('alert_id')).order_by('day'),
            'alerts_by_assignee': alerts.values(
                'assignee__username',
                'assignee__first_name',
                'assignee__last_name'
            ).annotate(count=Count('alert_id')),
            'period': {
                'from': date_from,
                'to': timezone.now(),
                'days': days
            }
        }
    
    elif report_type == 'cases':
        # Relatório de casos
        cases = Case.objects.filter(
            organization=organization,
            created_at__gte=date_from
        )
        
        data = {
            'total_cases': cases.count(),
            'cases_by_severity': cases.values('severity__name').annotate(count=Count('case_id')),
            'cases_by_status': cases.values('status__name').annotate(count=Count('case_id')),
            'cases_by_day': cases.annotate(
                day=TruncDay('created_at')
            ).values('day').annotate(count=Count('case_id')).order_by('day'),
            'cases_by_assignee': cases.values(
                'assignee__username',
                'assignee__first_name',
                'assignee__last_name'
            ).annotate(count=Count('case_id')),
            'avg_resolution_time': cases.filter(
                closed_at__isnull=False
            ).annotate(
                resolution_time=F('closed_at') - F('created_at')
            ).aggregate(avg_time=Avg('resolution_time')),
            'period': {
                'from': date_from,
                'to': timezone.now(),
                'days': days
            }
        }
    
    elif report_type == 'observables':
        # Relatório de observáveis
        observables = Observable.objects.filter(
            added_at__gte=date_from,
            added_by__profile__organization=organization
        )
        
        data = {
            'total_observables': observables.count(),
            'observables_by_type': observables.values('type__name').annotate(count=Count('observable_id')),
            'iocs_count': observables.filter(is_ioc=True).count(),
            'tlp_distribution': observables.values('tlp_level__name').annotate(count=Count('observable_id')),
            'observables_by_day': observables.annotate(
                day=TruncDay('added_at')
            ).values('day').annotate(count=Count('observable_id')).order_by('day'),
            'top_observables': observables.values('type__name', 'value').annotate(
                count=Count('case_observables') + Count('alert_observables')
            ).order_by('-count')[:10],
            'period': {
                'from': date_from,
                'to': timezone.now(),
                'days': days
            }
        }
    
    else:
        # Lista de relatórios disponíveis
        data = {
            'available_reports': [
                {
                    'type': 'alerts',
                    'name': 'Relatório de Alertas',
                    'description': 'Estatísticas de alertas por severidade, status e fonte'
                },
                {
                    'type': 'cases',
                    'name': 'Relatório de Casos',
                    'description': 'Estatísticas de casos por severidade, status e tempo de resolução'
                },
                {
                    'type': 'observables',
                    'name': 'Relatório de Observáveis',
                    'description': 'Estatísticas de observáveis por tipo, TLP e frequência'
                }
            ]
        }
    
    return Response(data)

class ObservableViewSet(viewsets.ModelViewSet):
    queryset = Observable.objects.all()
    serializer_class = ObservableSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'observable:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'observable:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'observable:edit'
        elif self.action == 'destroy':
            self.required_permission = 'observable:delete'
        return super().get_permissions()
    
    @audit_action(entity_type='OBSERVABLE', action_type='CREATE')
    def perform_create(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='OBSERVABLE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='OBSERVABLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

class CaseObservableViewSet(viewsets.ModelViewSet):
    queryset = CaseObservable.objects.all()
    serializer_class = CaseObservableSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'observable:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'observable:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'observable:edit'
        elif self.action == 'destroy':
            self.required_permission = 'observable:delete'
        return super().get_permissions()
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return CaseObservable.objects.filter(case__case_id=case_id, case__organization_id=org_id)
        return CaseObservable.objects.none()
    
    @audit_action(entity_type='CASE_OBSERVABLE', action_type='CREATE')
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        user = self.request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            # Processar os observáveis
            observable_data = self.request.data
            
            # Buscar ou criar o tipo de observável
            type_id = observable_data.get('type_id')
            type_obj = get_object_or_404(ObservableType, pk=type_id)
            
            # Buscar ou criar o observável
            value = observable_data.get('value')
            
            # Verificar se já existe um observável com este valor e tipo
            observable, created = Observable.objects.get_or_create(
                value=value,
                type=type_obj,
                defaults={
                    'description': observable_data.get('description', ''),
                    'tags': observable_data.get('tags', []),
                    'is_ioc': observable_data.get('is_ioc', False),
                    'added_by': user
                }
            )
            
            # TLP e PAP, se fornecidos
            tlp_id = observable_data.get('tlp_id')
            pap_id = observable_data.get('pap_id')
            
            if tlp_id:
                tlp = get_object_or_404(TLPLevel, pk=tlp_id)
                observable.tlp_level = tlp
            
            if pap_id:
                pap = get_object_or_404(PAPLevel, pk=pap_id)
                observable.pap_level = pap
            
            observable.save()
            
            # Associar o observável ao caso
            case_observable = serializer.save(
                case=case,
                observable=observable,
                sighted_at=observable_data.get('sighted_at', timezone.now())
            )
            
            # Adicionar evento na timeline
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='OBSERVABLE_ADDED',
                description=f"Observável '{observable.value}' ({observable.type.name}) adicionado por {user.get_full_name() or user.username}",
                actor=user,
                target_entity_type='Observable',
                target_entity_id=str(observable.observable_id),
                metadata={
                    'observable_value': observable.value,
                    'observable_type': observable.type.name,
                    'is_ioc': observable.is_ioc,
                    'tlp_level': str(observable.tlp_level) if observable.tlp_level else None,
                    'pap_level': str(observable.pap_level) if observable.pap_level else None
                }
            )
            
            return case_observable
        else:
            raise PermissionError("Usuário não pode adicionar observáveis a este caso")
    
    @audit_action(entity_type='CASE_OBSERVABLE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='CASE_OBSERVABLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        case_observable = self.get_object()
        user = request.user
        case = case_observable.case
        observable = case_observable.observable
        
        # Adicionar evento na timeline antes de excluir
        create_timeline_event(
            case=case,
            organization=case.organization,
            event_type='OBSERVABLE_REMOVED',
            description=f"Observável '{observable.value}' ({observable.type.name}) removido por {user.get_full_name() or user.username}",
            actor=user,
            target_entity_type='Observable',
            target_entity_id=str(observable.observable_id),
            metadata={
                'observable_value': observable.value,
                'observable_type': observable.type.name
            }
        )
        
        return super().destroy(request, *args, **kwargs)

class AlertObservableViewSet(viewsets.ModelViewSet):
    queryset = AlertObservable.objects.all()
    serializer_class = AlertObservableSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'observable:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'observable:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'observable:edit'
        elif self.action == 'destroy':
            self.required_permission = 'observable:delete'
        return super().get_permissions()
    
    def get_queryset(self):
        alert_id = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if alert_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return AlertObservable.objects.filter(alert__alert_id=alert_id, alert__organization_id=org_id)
        return AlertObservable.objects.none()
    
    @audit_action(entity_type='ALERT_OBSERVABLE', action_type='CREATE')
    def perform_create(self, serializer):
        alert_id = self.kwargs.get('alert_pk')
        alert = get_object_or_404(Alert, alert_id=alert_id)
        
        # Verificar se o usuário pertence à mesma organização do alerta
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == alert.organization:
            # Processar os observáveis (similar ao CaseObservableViewSet)
            observable_data = self.request.data
            
            # Buscar ou criar o tipo de observável
            type_id = observable_data.get('type_id')
            type_obj = get_object_or_404(ObservableType, pk=type_id)
            
            # Buscar ou criar o observável
            value = observable_data.get('value')
            
            # Verificar se já existe um observável com este valor e tipo
            observable, created = Observable.objects.get_or_create(
                value=value,
                type=type_obj,
                defaults={
                    'description': observable_data.get('description', ''),
                    'tags': observable_data.get('tags', []),
                    'is_ioc': observable_data.get('is_ioc', False),
                    'added_by': user
                }
            )
            
            # TLP e PAP, se fornecidos
            tlp_id = observable_data.get('tlp_id')
            pap_id = observable_data.get('pap_id')
            
            if tlp_id:
                tlp = get_object_or_404(TLPLevel, pk=tlp_id)
                observable.tlp_level = tlp
            
            if pap_id:
                pap = get_object_or_404(PAPLevel, pk=pap_id)
                observable.pap_level = pap
            
            observable.save()
            
            # Associar o observável ao alerta
            result = serializer.save(
                alert=alert,
                observable=observable,
                sighted_at=observable_data.get('sighted_at', timezone.now())
            )
            
            # Incrementar contador de artefatos
            alert.artifact_count += 1
            alert.save()
            
            return result
        else:
            raise PermissionError("Usuário não pode adicionar observáveis a este alerta")
    
    @audit_action(entity_type='ALERT_OBSERVABLE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='ALERT_OBSERVABLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        alert_observable = self.get_object()
        alert = alert_observable.alert
        
        # Decrementar contador de artefatos
        if alert.artifact_count > 0:
            alert.artifact_count -= 1
            alert.save(update_fields=['artifact_count'])
        
        return super().destroy(request, *args, **kwargs)

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_organizations'  # Permissão de alto nível
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return AuditLog.objects.filter(organization_id=org_id)
        return AuditLog.objects.none()


class NotificationEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for notification events (readonly)
    """
    queryset = NotificationEvent.objects.all()
    serializer_class = NotificationEventSerializer
    permission_classes = [permissions.IsAuthenticated]


class NotificationChannelViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing notification channels
    """
    serializer_class = NotificationChannelSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:manage'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return NotificationChannel.objects.filter(organization=user.profile.organization)
        return NotificationChannel.objects.none()
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            raise PermissionError("User must belong to an organization")
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """
        Test a notification channel
        """
        channel = self.get_object()
        
        # Create a test payload
        test_payload = {
            'message': 'This is a test notification',
            'timestamp': timezone.now().isoformat(),
            'sender': request.user.username
        }
        
        # Send test notification
        success, response_details = NotificationService._send_notification(
            channel=channel, 
            message="This is a test notification from your Incident Response Platform", 
            payload=test_payload
        )
        
        return Response({
            'success': success,
            'message': 'Test notification sent successfully' if success else 'Failed to send test notification',
            'details': response_details
        })


class NotificationRuleViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing notification rules
    """
    serializer_class = NotificationRuleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:manage'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return NotificationRule.objects.filter(organization=user.profile.organization)
        return NotificationRule.objects.none()
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            raise PermissionError("User must belong to an organization")
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """
        Test a notification rule with a sample payload
        """
        rule = self.get_object()
        
        # Get or create a test payload
        test_payload = request.data.get('payload', {})
        if not test_payload:
            # Create default test payload based on event type
            event_name = rule.event_type.event_name
            if 'ALERT' in event_name:
                test_payload = {
                    'alert_id': 'test-alert-id',
                    'title': 'Test Alert',
                    'description': 'This is a test alert',
                    'severity': 'Critical',
                    'status': 'New',
                    'created_at': timezone.now().isoformat(),
                    'organization_id': rule.organization.organization_id,
                    'organization_name': rule.organization.name,
                }
            elif 'CASE' in event_name:
                test_payload = {
                    'case_id': 'test-case-id',
                    'title': 'Test Case',
                    'description': 'This is a test case',
                    'severity': 'High',
                    'status': 'Open',
                    'created_at': timezone.now().isoformat(),
                    'organization_id': rule.organization.organization_id,
                    'organization_name': rule.organization.name,
                }
            else:
                test_payload = {
                    'event_name': event_name,
                    'timestamp': timezone.now().isoformat(),
                    'organization_id': rule.organization.organization_id,
                    'organization_name': rule.organization.name,
                    'test': True
                }
        
        # Check conditions
        conditions_met = NotificationService._evaluate_conditions(rule.conditions, test_payload)
        
        # If conditions are met, send test notification
        if conditions_met:
            message = NotificationService._render_template(rule.message_template, test_payload) if rule.message_template else json.dumps(test_payload)
            success, response_details = NotificationService._send_notification(
                channel=rule.channel, 
                message=message, 
                payload=test_payload
            )
            
            return Response({
                'conditions_met': True,
                'notification_sent': success,
                'message': message,
                'details': response_details
            })
        else:
            return Response({
                'conditions_met': False,
                'message': 'Test payload does not meet rule conditions',
                'rule_conditions': rule.conditions,
                'test_payload': test_payload
            })


class NotificationLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing notification logs (readonly)
    """
    serializer_class = NotificationLogSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:view'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return NotificationLog.objects.filter(organization=user.profile.organization)
        return NotificationLog.objects.none()


class NotificationViewSet(viewsets.ViewSet):
    """
    ViewSet for triggering notifications manually and testing notification rules
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=['post'])
    def trigger_event(self, request):
        """
        Manually trigger a notification event
        """
        user = request.user
        if not hasattr(user, 'profile') or not user.profile.organization:
            return Response(
                {'detail': 'User not associated with an organization'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        event_name = request.data.get('event_name')
        payload = request.data.get('payload', {})
        
        if not event_name:
            return Response(
                {'detail': 'event_name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Process the event using the notification service
            notification_logs = NotificationService.process_event(
                event_name=event_name,
                payload=payload,
                organization=user.profile.organization
            )
            
            if notification_logs:
                return Response({
                    'status': 'success',
                    'message': f'Event processed successfully. {len(notification_logs)} notification(s) sent.',
                    'notification_logs': notification_logs
                })
            else:
                return Response({
                    'status': 'info',
                    'message': 'Event processed, but no matching rules found to trigger notifications.'
                })
            
        except Exception as e:
            return Response(
                {'detail': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class HelloWorldView(APIView):
    def get(self, request):
        return Response({'message': 'Hello, world!'}, status=status.HTTP_200_OK)

class LoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        token = Token.objects.get(key=response.data['token'])
        return Response({'token': token.key, 'user_id': token.user_id})

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)

# Timeline viewclass TimelineEventViewSet(viewsets.ReadOnlyModelViewSet):    """    API endpoint for retrieving timeline events for a specific case.    Timeline events provide a chronological view of all activities related to a case.    """    queryset = TimelineEvent.objects.all()    serializer_class = TimelineEventSerializer    permission_classes = [permissions.IsAuthenticated, HasRolePermission]    required_permission = 'case:view'        def get_queryset(self):        case_id = self.kwargs.get('case_pk')        user = self.request.user                if case_id:            if hasattr(user, 'profile') and user.profile.organization:                org_id = user.profile.organization.organization_id                return TimelineEvent.objects.filter(                    case__case_id=case_id,                     organization_id=org_id                ).order_by('-occurred_at')        return TimelineEvent.objects.none()            @action(detail=False, methods=['post'])    @audit_action(entity_type='TIMELINE_EVENT', action_type='CREATE')    def create_event(self, request, case_pk=None):        """        Criar evento manualmente na timeline        """        case = get_object_or_404(Case, case_id=case_pk)        user = request.user                # Verificar se o usuário pertence à mesma organização do caso        if not hasattr(user, 'profile') or not user.profile.organization or user.profile.organization != case.organization:            raise PermissionError("Usuário não pode adicionar eventos a este caso")                # Extrair dados do request        event_type = request.data.get('event_type', 'MANUAL_EVENT')        description = request.data.get('description')        metadata = request.data.get('metadata', {})        occurred_at = request.data.get('occurred_at')                if not description:            return Response(                {"detail": "Descrição do evento é obrigatória"},                 status=status.HTTP_400_BAD_REQUEST            )                # Criar evento        event = create_timeline_event(            case=case,            organization=case.organization,            event_type=event_type,            description=description,            actor=user,            metadata=metadata,            occurred_at=occurred_at        )                # Serializar e retornar        serializer = self.get_serializer(event)        return Response(serializer.data, status=status.HTTP_201_CREATED)

# Function to automatically create timeline eventsdef create_timeline_event(case, organization, event_type, description, actor,                          target_entity_type=None, target_entity_id=None, metadata=None,                         occurred_at=None):    """    Helper function to create timeline events.    This should be called whenever a significant action happens in a case.    """    return TimelineEvent.objects.create(        case=case,        organization=organization,        event_type=event_type,        description=description,        actor=actor,        target_entity_type=target_entity_type,        target_entity_id=target_entity_id,        metadata=metadata or {},        occurred_at=occurred_at or timezone.now()    )

# MITRE ATT&CK views
class MitreTacticViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for retrieving MITRE ATT&CK tactics.
    This provides read-only access to the tactics imported from the MITRE ATT&CK framework.
    """
    queryset = MitreTactic.objects.all()
    serializer_class = MitreTacticSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = MitreTactic.objects.all()
        
        # Filter by version if provided
        version = self.request.query_params.get('version', None)
        if version:
            queryset = queryset.filter(version=version)
            
        return queryset.order_by('name')

class MitreTechniqueViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for retrieving MITRE ATT&CK techniques.
    This provides read-only access to the techniques imported from the MITRE ATT&CK framework.
    """
    queryset = MitreTechnique.objects.all()
    serializer_class = MitreTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = MitreTechnique.objects.all()
        
        # Apply filters based on query parameters
        tactic_id = self.request.query_params.get('tactic_id', None)
        is_subtechnique = self.request.query_params.get('is_subtechnique', None)
        version = self.request.query_params.get('version', None)
        search = self.request.query_params.get('search', None)
        
        if tactic_id:
            queryset = queryset.filter(tactics__tactic_id=tactic_id)
        
        if is_subtechnique is not None:
            is_sub = is_subtechnique.lower() in ['true', '1', 'yes']
            queryset = queryset.filter(is_subtechnique=is_sub)
        
        if version:
            queryset = queryset.filter(version=version)
            
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | 
                Q(technique_id__icontains=search) |
                Q(description__icontains=search)
            )
            
        return queryset.order_by('technique_id')

class CaseMitreTechniqueViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing MITRE ATT&CK techniques associated with cases.
    """
    queryset = CaseMitreTechnique.objects.all()
    serializer_class = CaseMitreTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:edit'
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return CaseMitreTechnique.objects.filter(
                    case__case_id=case_id, 
                    case__organization_id=org_id
                )
        return CaseMitreTechnique.objects.none()
    
    @audit_action(entity_type='CASE_MITRE_TECHNIQUE', action_type='CREATE')
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        user = self.request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if not hasattr(user, 'profile') or not user.profile.organization or user.profile.organization != case.organization:
            raise PermissionError("Usuário não pode adicionar técnicas MITRE ATT&CK a este caso")
        
        technique_id = self.request.data.get('technique_id')
        technique = get_object_or_404(MitreTechnique, technique_id=technique_id)
        
        # Salvar a associação
        case_technique = serializer.save(
            case=case,
            technique=technique,
            linked_by=user
        )
        
        # Adicionar evento na timeline
        create_timeline_event(
            case=case,
            organization=case.organization,
            event_type='MITRE_TTP_LINKED',
            description=f"Técnica MITRE ATT&CK '{technique.name}' ({technique.technique_id}) associada ao caso",
            actor=user,
            target_entity_type='MitreTechnique',
            target_entity_id=technique.technique_id
        )
        
        return case_technique
    
    @audit_action(entity_type='CASE_MITRE_TECHNIQUE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        case_mitre = self.get_object()
        case = case_mitre.case
        technique = case_mitre.technique
        user = request.user
        
        # Adicionar evento na timeline antes de excluir
        create_timeline_event(
            case=case,
            organization=case.organization,
            event_type='MITRE_TTP_UNLINKED',
            description=f"Técnica MITRE ATT&CK '{technique.name}' ({technique.technique_id}) removida do caso",
            actor=user,
            target_entity_type='MitreTechnique',
            target_entity_id=technique.technique_id
        )
        
        return super().destroy(request, *args, **kwargs)

class AlertMitreTechniqueViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing MITRE ATT&CK techniques associated with alerts.
    """
    queryset = AlertMitreTechnique.objects.all()
    serializer_class = AlertMitreTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:edit'
    
    def get_queryset(self):
        alert_id = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if alert_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return AlertMitreTechnique.objects.filter(
                    alert__alert_id=alert_id, 
                    alert__organization_id=org_id
                )
        return AlertMitreTechnique.objects.none()
    
    @audit_action(entity_type='ALERT_MITRE_TECHNIQUE', action_type='CREATE')
    def perform_create(self, serializer):
        alert_id = self.kwargs.get('alert_pk')
        alert = get_object_or_404(Alert, alert_id=alert_id)
        user = self.request.user
        
        # Verificar se o usuário pertence à mesma organização do alerta
        if not hasattr(user, 'profile') or not user.profile.organization or user.profile.organization != alert.organization:
            raise PermissionError("Usuário não pode adicionar técnicas MITRE ATT&CK a este alerta")
        
        technique_id = self.request.data.get('technique_id')
        technique = get_object_or_404(MitreTechnique, technique_id=technique_id)
        
        # Salvar a associação
        return serializer.save(
            alert=alert,
            technique=technique,
            linked_by=user
        )
    
    
    @audit_action(entity_type='ALERT_MITRE_TECHNIQUE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def import_mitre_attack(request):
    """
    Endpoint para importar ou atualizar os dados do MITRE ATT&CK.
    Este endpoint pode baixar o arquivo STIX do repositório MITRE CTI ou
    processar um arquivo STIX enviado pelo usuário.
    """
    # Verificar permissão
    if not request.user.has_perm('manage_mitre_data'):
        return Response({"error": "Sem permissão para importar dados MITRE ATT&CK"}, 
                        status=status.HTTP_403_FORBIDDEN)
    
    try:
        # Parâmetros da importação
        url = request.data.get('stix_url')
        version = request.data.get('version', 'current')
        file_data = request.data.get('stix_data')
        
        if url:
            # Baixar o arquivo STIX da URL fornecida
            response = requests.get(url)
            stix_data = response.json()
        elif file_data:
            # Usar o arquivo STIX fornecido
            if isinstance(file_data, str):
                stix_data = json.loads(file_data)
            else:
                stix_data = file_data
        else:
            # URL padrão do repositório MITRE CTI para Enterprise
            default_url = f"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = requests.get(default_url)
            stix_data = response.json()
        
        # Processar os dados STIX
        tactics_created = 0
        techniques_created = 0
        relationships_created = 0
        
        # Extrair versão dos dados se não fornecida
        if not version or version == 'current':
            for obj in stix_data.get('objects', []):
                if obj.get('type') == 'x-mitre-matrix':
                    version = obj.get('name', '').split('-')[-1].strip() or 'unknown'
                    break
        
        # Processar táticas
        tactics = {}
        for obj in stix_data.get('objects', []):
            if obj.get('type') == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', '')
                if tactic_id.startswith('TA'):
                    name = obj.get('name', '')
                    description = obj.get('description', '')
                    url = obj.get('external_references', [{}])[0].get('url', '')
                    
                    tactic, created = MitreTactic.objects.update_or_create(
                        tactic_id=tactic_id,
                        defaults={
                            'name': name,
                            'description': description,
                            'url': url,
                            'version': version
                        }
                    )
                    
                    tactics[obj.get('id')] = tactic
                    if created:
                        tactics_created += 1
        
        # Processar técnicas
        techniques = {}
        for obj in stix_data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                if technique_id.startswith('T'):
                    name = obj.get('name', '')
                    description = obj.get('description', '')
                    url = obj.get('external_references', [{}])[0].get('url', '')
                    is_subtechnique = '.' in technique_id
                    
                    # Parent technique ID para subtécnicas
                    parent_technique = None
                    if is_subtechnique:
                        parent_id = technique_id.split('.')[0]
                        parent_technique = MitreTechnique.objects.filter(technique_id=parent_id).first()
                    
                    technique, created = MitreTechnique.objects.update_or_create(
                        technique_id=technique_id,
                        defaults={
                            'name': name,
                            'description': description,
                            'url': url,
                            'is_subtechnique': is_subtechnique,
                            'parent_technique': parent_technique,
                            'version': version
                        }
                    )
                    
                    techniques[obj.get('id')] = technique
                    if created:
                        techniques_created += 1
        
        # Processar relacionamentos entre técnicas e táticas
        for obj in stix_data.get('objects', []):
            if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses':
                source_ref = obj.get('source_ref')
                target_ref = obj.get('target_ref')
                
                if source_ref in techniques and target_ref in tactics:
                    technique = techniques[source_ref]
                    tactic = tactics[target_ref]
                    
                    # Criar relacionamento
                    rel, created = TechniqueTactic.objects.get_or_create(
                        technique=technique,
                        tactic=tactic
                    )
                    
                    if created:
                        relationships_created += 1
        
        return Response({
            'success': True,
            'version': version,
            'tactics_created_or_updated': tactics_created,
            'techniques_created_or_updated': techniques_created,
            'technique_tactic_relationships_created': relationships_created
        })
        
    except Exception as e:
        return Response({
            'error': f"Erro ao importar dados MITRE ATT&CK: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Knowledge Base views
class KBCategoryViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing knowledge base categories.
    """
    queryset = KBCategory.objects.all()
    serializer_class = KBCategorySerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'kb:manage_categories'
    
    def get_queryset(self):
        user = self.request.user
        
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            # Return global categories (organization=None) and org-specific categories
            return KBCategory.objects.filter(
                Q(organization__isnull=True) | Q(organization_id=org_id)
            )
        return KBCategory.objects.filter(organization__isnull=True)
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class KBArticleViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing knowledge base articles.
    """
    queryset = KBArticle.objects.all()
    serializer_class = KBArticleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'kb:view'
    lookup_field = 'slug'
    lookup_url_kwarg = 'slug_or_id'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'kb:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'kb:edit'
        elif self.action == 'destroy':
            self.required_permission = 'kb:delete'
        elif self.action == 'publish':
            self.required_permission = 'kb:publish'
        return super().get_permissions()
    
    def get_queryset(self):
        user = self.request.user
        
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            # Return global articles (organization=None) and org-specific articles
            queryset = KBArticle.objects.filter(
                Q(organization__isnull=True) | Q(organization_id=org_id)
            )
            
            # Filter by status if specified
            status_param = self.request.query_params.get('status', None)
            if status_param:
                statuses = status_param.split(',')
                queryset = queryset.filter(status__in=statuses)
            elif not self.detail:
                # By default, only show published articles in list view
                queryset = queryset.filter(status='PUBLISHED')
            
            # Filter by category if specified
            category_id = self.request.query_params.get('category_id', None)
            if category_id:
                queryset = queryset.filter(category_id=category_id)
            
            # Filter by search term if specified
            search = self.request.query_params.get('search', None)
            if search:
                queryset = queryset.filter(
                    Q(title__icontains=search) | 
                    Q(content__icontains=search) |
                    Q(tags__contains=[search])
                )
            
            return queryset.order_by('-updated_at')
        
        # For users without organization, only show global published articles
        return KBArticle.objects.filter(
            organization__isnull=True,
            status='PUBLISHED'
        )
    
    def get_object(self):
        queryset = self.get_queryset()
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
        lookup_value = self.kwargs[lookup_url_kwarg]
        
        # Try to find by UUID first
        try:
            if '-' in lookup_value:
                return queryset.get(article_id=lookup_value)
        except (KBArticle.DoesNotExist, ValueError):
            pass
        
        # Then by slug
        obj = get_object_or_404(queryset, slug=lookup_value)
        self.check_object_permissions(self.request, obj)
        return obj
    
    @audit_action(entity_type='KB_ARTICLE', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        
        if not hasattr(user, 'profile') or not user.profile.organization:
            raise PermissionError("Usuário não possui organização")
        
        # Criar o artigo
        article = serializer.save(
            author=user,
            organization=user.profile.organization
        )
        
        # Criar versão inicial
        KBArticleVersion.objects.create(
            article=article,
            version_number=1,
            title=article.title,
            content=article.content,
            author=user
        )
        
        return article
    
    @audit_action(entity_type='KB_ARTICLE', action_type='UPDATE')
    def perform_update(self, serializer):
        user = self.request.user
        article = self.get_object()
        
        # Verificar se o conteúdo ou título mudou
        content_changed = 'content' in serializer.validated_data and serializer.validated_data['content'] != article.content
        title_changed = 'title' in serializer.validated_data and serializer.validated_data['title'] != article.title
        
        # Se mudou conteúdo ou título, incrementar versão
        if content_changed or title_changed:
            new_version = article.version + 1
            serializer.save(version=new_version)
            
            # Criar entrada na tabela de versões
            KBArticleVersion.objects.create(
                article=article,
                version_number=new_version,
                title=serializer.validated_data.get('title', article.title),
                content=serializer.validated_data.get('content', article.content),
                author=user
            )
        else:
            serializer.save()
    
    @audit_action(entity_type='KB_ARTICLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        article = self.get_object()
        
        # Mudar status para ARCHIVED em vez de excluir
        article.status = 'ARCHIVED'
        article.save()
        
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['post'])
    @audit_action(entity_type='KB_ARTICLE', action_type='PUBLISH')
    def publish(self, request, slug_or_id=None):
        """
        Action para publicar um artigo.
        """
        article = self.get_object()
        
        # Verificar se já está publicado
        if article.status == 'PUBLISHED':
            return Response({"detail": "Artigo já está publicado"}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        # Atualizar status e data de publicação
        article.status = 'PUBLISHED'
        article.published_at = timezone.now()
        article.save()
        
        serializer = self.get_serializer(article)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def versions(self, request, slug_or_id=None):
        """
        Action para listar versões de um artigo.
        """
        article = self.get_object()
        versions = article.versions.all().order_by('-version_number')
        
        page = self.paginate_queryset(versions)
        if page is not None:
            serializer = KBArticleVersionSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = KBArticleVersionSerializer(versions, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'], url_path='versions/(?P<version_number>\d+)')
    def get_version(self, request, slug_or_id=None, version_number=None):
        """
        Action para obter uma versão específica de um artigo.
        """
        article = self.get_object()
        
        try:
            version = article.versions.get(version_number=version_number)
        except KBArticleVersion.DoesNotExist:
            return Response({"detail": "Versão não encontrada"}, 
                          status=status.HTTP_404_NOT_FOUND)
        
        serializer = KBArticleVersionSerializer(version)
        return Response(serializer.data)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def kb_search(request):
    """
    Endpoint para busca avançada na base de conhecimento.
    """
    user = request.user
    search_term = request.query_params.get('q', '')
    
    if not search_term:
        return Response({"detail": "Parâmetro de busca 'q' é obrigatório"}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    # Buscar artigos visíveis para o usuário
    if hasattr(user, 'profile') and user.profile.organization:
        org_id = user.profile.organization.organization_id
        queryset = KBArticle.objects.filter(
            Q(organization__isnull=True) | Q(organization_id=org_id),
            status='PUBLISHED'
        )
    else:
        queryset = KBArticle.objects.filter(
            organization__isnull=True,
            status='PUBLISHED'
        )
    
    # Busca em título, conteúdo e tags
    results = queryset.filter(
        Q(title__icontains=search_term) | 
        Q(content__icontains=search_term) |
        Q(tags__contains=[search_term])
    ).order_by('-updated_at')
    
    # Limitar resultados
    limit = int(request.query_params.get('limit', 20))
    results = results[:limit]
    
    # Serializar resultados
    serializer = KBArticleSerializer(results, many=True)
    
    return Response({
        'count': len(results),
        'results': serializer.data
    })

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def kb_related_articles(request, entity_type, entity_id):
    """
    Endpoint para sugerir artigos da base de conhecimento relacionados 
    a um caso, alerta ou outro objeto com base em palavras-chave.
    """
    user = request.user
    
    # Obter o objeto relacionado
    if entity_type.lower() == 'case':
        try:
            entity = Case.objects.get(case_id=entity_id)
            keywords = []
            
            # Extrair palavras-chave do título e descrição
            if entity.title:
                keywords.extend(entity.title.lower().split())
            if entity.description:
                keywords.extend(entity.description.lower().split())
                
            # Adicionar outros termos relevantes como severidade, status, etc.
            if entity.severity:
                keywords.append(entity.severity.name.lower())
            if entity.status:
                keywords.append(entity.status.name.lower())
                
        except Case.DoesNotExist:
            return Response({"detail": "Caso não encontrado"}, 
                           status=status.HTTP_404_NOT_FOUND)
    
    elif entity_type.lower() == 'alert':
        try:
            entity = Alert.objects.get(alert_id=entity_id)
            keywords = []
            
            # Extrair palavras-chave do título e descrição
            if entity.title:
                keywords.extend(entity.title.lower().split())
            if entity.description:
                keywords.extend(entity.description.lower().split())
                
            # Adicionar outros termos relevantes
            if entity.severity:
                keywords.append(entity.severity.name.lower())
            if entity.status:
                keywords.append(entity.status.name.lower())
            if entity.source_system:
                keywords.append(entity.source_system.lower())
                
        except Alert.DoesNotExist:
            return Response({"detail": "Alerta não encontrado"}, 
                           status=status.HTTP_404_NOT_FOUND)
    else:
        return Response({"detail": "Tipo de entidade não suportado"}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    # Filtrar palavras-chave (remover preposições, artigos, etc.)
    stopwords = ['a', 'o', 'e', 'de', 'do', 'da', 'em', 'no', 'na', 'para', 'com', 'por']
    keywords = [k for k in keywords if len(k) > 3 and k not in stopwords]
    
    # Limite de palavras-chave
    keywords = keywords[:10]
    
    # Buscar artigos visíveis para o usuário
    if hasattr(user, 'profile') and user.profile.organization:
        org_id = user.profile.organization.organization_id
        queryset = KBArticle.objects.filter(
            Q(organization__isnull=True) | Q(organization_id=org_id),
            status='PUBLISHED'
        )
    else:
        queryset = KBArticle.objects.filter(
            organization__isnull=True,
            status='PUBLISHED'
        )
    
    # Buscar artigos relacionados com as palavras-chave
    results = []
    for keyword in keywords:
        articles = queryset.filter(
            Q(title__icontains=keyword) | 
            Q(content__icontains=keyword) |
            Q(tags__contains=[keyword])
        )
        
        for article in articles:
            # Adicionar score de relevância baseado no número de keywords encontradas
            score = 0
            for k in keywords:
                if k in article.title.lower():
                    score += 3  # Peso maior para matches no título
                if k in article.content.lower():
                    score += 1  # Peso menor para matches no conteúdo
                if article.tags and k in [t.lower() for t in article.tags]:
                    score += 2  # Peso médio para matches nas tags
            
            # Adicionar à lista de resultados se tiver score mínimo
            if score > 0:
                result = {
                    'article': article,
                    'score': score
                }
                
                # Verificar se já está nos resultados
                existing = next((r for r in results if r['article'].article_id == article.article_id), None)
                if existing:
                    # Atualizar score se for maior
                    if score > existing['score']:
                        existing['score'] = score
                else:
                    results.append(result)
    
    # Ordenar por score e limitar resultados
    results = sorted(results, key=lambda x: x['score'], reverse=True)[:5]
    
    # Serializar resultados
    serialized_results = []
    for result in results:
        article_data = KBArticleSerializer(result['article']).data
        serialized_results.append({
            'article': article_data,
            'relevance_score': result['score']
        })
    
    return Response({
        'count': len(serialized_results),
        'keywords_used': keywords,
        'results': serialized_results
    })

class MetricViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for listing and retrieving metrics.
    Metrics are system-defined and cannot be modified via API.
    """
    queryset = Metric.objects.all()
    serializer_class = MetricSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=True, methods=['get'])
    def data(self, request, pk=None):
        """
        Get metric data for a specific period
        """
        metric = self.get_object()
        user = request.user
        
        if not hasattr(user, 'profile') or not user.profile.organization:
            return Response(
                {'detail': 'User not associated with an organization'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Parse query parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        granularity = request.query_params.get('granularity', 'DAILY')
        
        # Parse dimensions from query params
        dimensions = {}
        for key, value in request.query_params.items():
            if key.startswith('dimension_'):
                dimension_name = key[10:]  # Remove 'dimension_' prefix
                dimensions[dimension_name] = value
        
        # Validate required parameters
        if not start_date or not end_date:
            return Response(
                {'detail': 'start_date and end_date are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Convert string dates to datetime
            from django.utils.dateparse import parse_date
            start_date = parse_date(start_date)
            end_date = parse_date(end_date)
            
            if not start_date or not end_date:
                raise ValueError("Invalid date format")
            
            # Get metric data
            data = MetricsService.get_metric_data(
                metric=metric,
                organization=user.profile.organization,
                start_date=start_date,
                end_date=end_date,
                granularity=granularity,
                dimensions=dimensions
            )
            
            return Response(data)
            
        except Exception as e:
            return Response(
                {'detail': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class MetricSnapshotViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for retrieving metric snapshots
    """
    serializer_class = MetricSnapshotSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return MetricSnapshot.objects.filter(organization=user.profile.organization)
        return MetricSnapshot.objects.none()
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by metric if provided
        metric_id = self.request.query_params.get('metric_id')
        if metric_id:
            queryset = queryset.filter(metric__metric_id=metric_id)
        
        # Filter by date range if provided
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        if start_date:
            queryset = queryset.filter(date__gte=start_date)
        if end_date:
            queryset = queryset.filter(date__lte=end_date)
        
        # Filter by granularity if provided
        granularity = self.request.query_params.get('granularity')
        if granularity:
            queryset = queryset.filter(granularity=granularity)
        
        return queryset


class DashboardViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing dashboards
    """
    serializer_class = DashboardSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return Dashboard.objects.filter(
                models.Q(organization=user.profile.organization) | 
                models.Q(is_system=True)
            )
        return Dashboard.objects.filter(is_system=True)  # Only system dashboards for users without org
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(
                organization=user.profile.organization,
                created_by=user
            )
        else:
            raise exceptions.PermissionDenied("User must belong to an organization to create dashboards")
    
    def perform_update(self, serializer):
        dashboard = self.get_object()
        
        # Prevent updating system dashboards unless user is a system admin
        if dashboard.is_system and not self.request.user.profile.is_system_admin:
            raise exceptions.PermissionDenied("Cannot modify system dashboards")
        
        serializer.save()
    
    def perform_destroy(self, instance):
        # Prevent deleting system dashboards
        if instance.is_system:
            raise exceptions.PermissionDenied("Cannot delete system dashboards")
        
        instance.delete()


class DashboardWidgetViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing dashboard widgets
    """
    serializer_class = DashboardWidgetSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            # Get dashboards this user has access to
            accessible_dashboards = Dashboard.objects.filter(
                models.Q(organization=user.profile.organization) | 
                models.Q(is_system=True)
            ).values_list('dashboard_id', flat=True)
            
            return DashboardWidget.objects.filter(dashboard__dashboard_id__in=accessible_dashboards)
        
        # User without org can only see widgets from system dashboards
        system_dashboards = Dashboard.objects.filter(is_system=True).values_list('dashboard_id', flat=True)
        return DashboardWidget.objects.filter(dashboard__dashboard_id__in=system_dashboards)
    
    def perform_create(self, serializer):
        dashboard = serializer.validated_data.get('dashboard')
        
        # Check if user has permission to modify this dashboard
        user = self.request.user
        if dashboard.is_system and not user.profile.is_system_admin:
            raise exceptions.PermissionDenied("Cannot add widgets to system dashboards")
        
        if dashboard.organization and (
            not hasattr(user, 'profile') or 
            not user.profile.organization or 
            user.profile.organization.id != dashboard.organization.id
        ):
            raise exceptions.PermissionDenied("Cannot add widgets to dashboards from other organizations")
        
        serializer.save()
    
    def perform_update(self, serializer):
        widget = self.get_object()
        
        # Prevent updating widgets in system dashboards
        if widget.dashboard.is_system and not self.request.user.profile.is_system_admin:
            raise exceptions.PermissionDenied("Cannot modify widgets in system dashboards")
        
        serializer.save()
    
    def perform_destroy(self, instance):
        # Prevent deleting widgets from system dashboards
        if instance.dashboard.is_system and not self.request.user.profile.is_system_admin:
            raise exceptions.PermissionDenied("Cannot delete widgets from system dashboards")
        
        instance.delete()
