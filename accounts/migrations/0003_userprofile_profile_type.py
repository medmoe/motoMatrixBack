# Generated by Django 4.2.1 on 2023-08-28 13:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='profile_type',
            field=models.CharField(choices=[('STORE', 'Store'), ('INDIVIDUAL', 'Individual'), ('JUNKYARD', 'Junkyard'), ('WHOLESALER', 'Wholesaler'), ('MANUFACTURER', 'Manufacturer')], default='PROVIDER', max_length=20),
        ),
    ]
