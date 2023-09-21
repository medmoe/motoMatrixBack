# Generated by Django 4.2.1 on 2023-08-29 00:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_userprofile_profile_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='profile_type',
            field=models.CharField(choices=[('PROVIDER', 'Provider'), ('CONSUMER', 'Consumer')], default='PROVIDER', max_length=20),
        ),
    ]
