# Generated by Django 4.2.2 on 2023-09-29 17:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0004_comment_share_like'),
    ]

    operations = [
        migrations.AddField(
            model_name='share',
            name='message',
            field=models.TextField(default=1),
            preserve_default=False,
        ),
    ]
