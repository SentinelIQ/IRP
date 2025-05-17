# Generated manually for MITRE ATT&CK integration

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='MitreTactic',
            fields=[
                ('tactic_id', models.CharField(max_length=50, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('short_name', models.CharField(max_length=100, null=True)),
                ('description', models.TextField()),
                ('url', models.CharField(max_length=255)),
                ('version', models.CharField(max_length=20)),
            ],
        ),
        migrations.CreateModel(
            name='MitreTechnique',
            fields=[
                ('technique_id', models.CharField(max_length=50, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('url', models.CharField(max_length=255)),
                ('is_subtechnique', models.BooleanField(default=False)),
                ('version', models.CharField(max_length=20)),
                ('parent_technique', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='subtechniques', to='mitre.mitretechnique')),
            ],
        ),
        migrations.CreateModel(
            name='TechniqueTactic',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tactic', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='mitre.mitretactic')),
                ('technique', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='mitre.mitretechnique')),
            ],
            options={
                'unique_together': {('technique', 'tactic')},
            },
        ),
        migrations.AddField(
            model_name='mitretechnique',
            name='tactics',
            field=models.ManyToManyField(related_name='techniques', through='mitre.TechniqueTactic', to='mitre.MitreTactic'),
        ),
    ] 