# Generated by Django 5.0.4 on 2024-05-07 10:42

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='subcategories', to='components.category')),
            ],
            options={
                'verbose_name_plural': 'Categories',
            },
        ),
        migrations.CreateModel(
            name='Component',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(blank=True, max_length=100)),
                ('description', models.TextField(blank=True)),
                ('manufacturer', models.CharField(blank=True, max_length=100)),
                ('price', models.DecimalField(decimal_places=2, max_digits=10, null=True)),
                ('stock', models.IntegerField(null=True)),
                ('image', models.ImageField(null=True, upload_to='component_images')),
                ('weight', models.DecimalField(decimal_places=2, max_digits=10, null=True)),
                ('dimensions', models.CharField(blank=True, max_length=100)),
                ('location', models.CharField(blank=True, max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.provider')),
            ],
            options={
                'ordering': ['created_at'],
            },
        ),
        migrations.CreateModel(
            name='AutoPart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vehicle_make', models.CharField(blank=True, max_length=100)),
                ('vehicle_model', models.CharField(blank=True, max_length=100)),
                ('vehicle_year', models.CharField(blank=True, max_length=100)),
                ('condition', models.CharField(blank=True, choices=[('NEW', 'New'), ('USED', 'Used'), ('REFURBISHED', 'Refurbished')], max_length=100)),
                ('oem_number', models.CharField(blank=True, max_length=100)),
                ('upc_number', models.CharField(blank=True, max_length=100)),
                ('category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='components.category')),
                ('component', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='components.component')),
            ],
            options={
                'ordering': ['id'],
            },
        ),
    ]
