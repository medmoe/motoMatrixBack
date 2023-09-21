# Generated by Django 4.2.1 on 2023-08-29 15:14

from django.db import migrations, models
import functools
import utils.helpers


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_userprofile_state_alter_userprofile_address_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='provider',
            name='store_logo',
            field=models.ImageField(null=True, upload_to=functools.partial(utils.helpers.uploaded_file_directory_path, *('store_logo/',), **{})),
        ),
    ]
