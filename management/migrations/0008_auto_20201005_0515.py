# Generated by Django 3.1.1 on 2020-10-04 21:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0007_auto_20201004_1047'),
    ]

    operations = [
        migrations.RenameField(
            model_name='bedspacing',
            old_name='user',
            new_name='bedspacer',
        ),
    ]
