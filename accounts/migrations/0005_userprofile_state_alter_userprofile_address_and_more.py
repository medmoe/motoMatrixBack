# Generated by Django 4.2.1 on 2023-08-29 13:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_alter_userprofile_profile_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='state',
            field=models.CharField(blank=True, max_length=20),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='address',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='city',
            field=models.CharField(blank=True, max_length=20),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='country',
            field=models.CharField(blank=True, max_length=20),
        ),
    ]
