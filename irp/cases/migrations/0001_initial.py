# Generated by Django 5.2.1 on 2025-05-17 03:31

import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('accounts', '0001_initial'),
        ('alerts', '0002_alter_alertmitretechnique_alert'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CaseObservable',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sighted_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='CaseSeverity',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, unique=True)),
                ('level_order', models.IntegerField()),
                ('color_code', models.CharField(max_length=7)),
            ],
            options={
                'verbose_name_plural': 'Case Severities',
            },
        ),
        migrations.CreateModel(
            name='CaseStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True)),
                ('is_default_open_status', models.BooleanField(default=False)),
                ('is_terminal_status', models.BooleanField(default=False)),
                ('color_code', models.CharField(default='#808080', max_length=7)),
            ],
            options={
                'verbose_name_plural': 'Case Statuses',
            },
        ),
        migrations.CreateModel(
            name='CaseTemplate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True)),
                ('default_title_format', models.CharField(blank=True, max_length=255)),
                ('default_tags', models.JSONField(blank=True, default=list)),
                ('predefined_tasks', models.JSONField(blank=True, default=list)),
                ('custom_field_definitions', models.JSONField(blank=True, default=list)),
            ],
        ),
        migrations.CreateModel(
            name='Task',
            fields=[
                ('task_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True)),
                ('due_date', models.DateField(blank=True, null=True)),
                ('order', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='TaskStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, unique=True)),
                ('color_code', models.CharField(default='#808080', max_length=7)),
            ],
        ),
        migrations.CreateModel(
            name='Case',
            fields=[
                ('case_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('title', models.CharField(db_index=True, max_length=255)),
                ('description', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('closed_at', models.DateTimeField(blank=True, null=True)),
                ('tags', models.JSONField(blank=True, default=list)),
                ('alerts', models.ManyToManyField(related_name='cases', to='alerts.alert')),
                ('assignee', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='assigned_cases', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='cases', to='accounts.organization')),
                ('reporter', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='reported_cases', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='CaseComment',
            fields=[
                ('comment_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('comment_text', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comments', to='cases.case')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='case_comments', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='CaseCustomFieldDefinition',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('technical_name', models.CharField(max_length=50)),
                ('field_type', models.CharField(choices=[('TEXT', 'Text'), ('NUMBER', 'Number'), ('BOOLEAN', 'Boolean'), ('DATE', 'Date'), ('SELECT', 'Select'), ('MULTI_SELECT', 'Multi Select')], max_length=20)),
                ('options', models.JSONField(blank=True, default=list)),
                ('is_required', models.BooleanField(default=False)),
                ('is_filterable', models.BooleanField(default=False)),
                ('organization', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='case_custom_field_definitions', to='accounts.organization')),
            ],
        ),
        migrations.CreateModel(
            name='CaseCustomFieldValue',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value_text', models.TextField(blank=True, null=True)),
                ('value_number', models.DecimalField(blank=True, decimal_places=5, max_digits=20, null=True)),
                ('value_boolean', models.BooleanField(blank=True, null=True)),
                ('value_date', models.DateTimeField(blank=True, null=True)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='custom_field_values', to='cases.case')),
                ('field_definition', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='field_values', to='cases.casecustomfielddefinition')),
            ],
        ),
        migrations.CreateModel(
            name='CaseMitreTechnique',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('linked_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('context_notes', models.TextField(blank=True, null=True)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='case_module_techniques', to='cases.case')),
                ('linked_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='case_technique_links', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
