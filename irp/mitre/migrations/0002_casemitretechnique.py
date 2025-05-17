# Generated manually for MITRE ATT&CK integration

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('cases', '0001_initial'),
        ('alerts', '0001_initial'),
        ('auth', '0012_alter_user_first_name_max_length'),
        ('mitre', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CaseMitreTechnique',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('added_at', models.DateTimeField(auto_now_add=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('kill_chain_phase', models.CharField(blank=True, help_text='Fase da kill chain onde esta técnica foi observada', max_length=100, null=True)),
                ('confidence_score', models.IntegerField(blank=True, help_text='Nível de confiança (1-100) de que esta técnica foi usada no ataque', null=True)),
                ('detection_method', models.CharField(blank=True, help_text='Como esta técnica foi detectada (ex: SIEM, EDR, análise manual)', max_length=255, null=True)),
                ('artifacts', models.TextField(blank=True, help_text='Artefatos relevantes que evidenciam esta técnica (IOCs, logs, etc)', null=True)),
                ('impact_level', models.CharField(blank=True, help_text='Nível de impacto desta técnica no caso (baixo, médio, alto)', max_length=50, null=True)),
                ('mitigation_status', models.CharField(blank=True, help_text='Status da mitigação (não iniciada, em andamento, concluída)', max_length=50, null=True)),
                ('first_observed', models.DateTimeField(blank=True, help_text='Quando esta técnica foi observada pela primeira vez', null=True)),
                ('last_observed', models.DateTimeField(blank=True, help_text='Quando esta técnica foi observada pela última vez', null=True)),
                ('added_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='auth.user')),
                ('alert', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='mitre_case_techniques', to='alerts.alert')),
                ('case', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='mitre_module_techniques', to='cases.case')),
                ('technique', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='mitre.mitretechnique')),
            ],
            options={
                'verbose_name': 'MITRE Technique Association',
                'verbose_name_plural': 'MITRE Technique Associations',
                'unique_together': {('case', 'technique'), ('alert', 'technique')},
            },
        ),
        migrations.CreateModel(
            name='AlertMitreTechnique',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('added_at', models.DateTimeField(auto_now_add=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('added_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='auth.user')),
                ('alert', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='mitre_module_techniques', to='alerts.alert')),
                ('technique', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='mitre.mitretechnique')),
            ],
            options={
                'unique_together': {('alert', 'technique')},
            },
        ),
    ] 