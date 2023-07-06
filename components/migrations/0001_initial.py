# Generated by Django 4.2.1 on 2023-06-14 14:18

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('accounts', '0002_provider_account_status_userprofile_is_provider'),
    ]

    operations = [
        migrations.CreateModel(
            name='AutoPart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True)),
                ('manufacturer', models.CharField(max_length=100)),
                ('price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('stock', models.IntegerField()),
                ('image', models.ImageField(blank=True, upload_to='component_images')),
                ('weight', models.DecimalField(decimal_places=2, max_digits=10)),
                ('dimensions', models.CharField(max_length=100)),
                ('location', models.CharField(max_length=100)),
                ('category', models.CharField(blank=True, choices=[('engine', 'Engine'), ('transmission', 'Transmission'), ('suspension', 'Suspension'), ('brakes', 'Brakes'), ('electrical', 'Electrical'), ('body', 'Body'), ('interior', 'Interior'), ('tires', 'Tires'), ('wheels', 'Wheels'), ('accessories', 'Accessories')], max_length=20)),
                ('vehicle_make', models.CharField(max_length=100)),
                ('vehicle_model', models.CharField(max_length=100)),
                ('vehicle_year', models.CharField(max_length=100)),
                ('condition', models.CharField(choices=[('new', 'New'), ('used', 'Used'), ('refurbished', 'Refurbished')], max_length=100)),
                ('OEM_number', models.CharField(blank=True, max_length=100)),
                ('UPC_number', models.CharField(blank=True, max_length=100)),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.provider')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
