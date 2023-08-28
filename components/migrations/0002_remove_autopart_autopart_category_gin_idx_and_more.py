# Generated by Django 4.2.1 on 2023-08-28 13:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('components', '0001_initial'),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name='autopart',
            name='autopart_category_gin_idx',
        ),
        migrations.RemoveIndex(
            model_name='autopart',
            name='autopart_condition_gin_idx',
        ),
        migrations.RemoveIndex(
            model_name='component',
            name='component_name_gin_idx',
        ),
        migrations.RemoveIndex(
            model_name='component',
            name='component_manufacturer_gin_idx',
        ),
        migrations.RemoveIndex(
            model_name='component',
            name='component_description_gin_idx',
        ),
    ]
