# Generated by Django 3.1.1 on 2020-12-14 15:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('actionPhishingWD', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Legitimate_site_list',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('link', models.CharField(max_length=500)),
            ],
        ),
    ]
