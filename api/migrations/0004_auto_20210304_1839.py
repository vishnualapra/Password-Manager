# Generated by Django 3.1.7 on 2021-03-04 13:09

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_auto_20210304_1724'),
    ]

    operations = [
        migrations.RenameField(
            model_name='member',
            old_name='Organization',
            new_name='organization',
        ),
    ]
