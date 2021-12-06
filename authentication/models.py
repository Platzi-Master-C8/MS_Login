from django.db import models

class User(models.Model):
    sub = models.CharField(max_length=150, unique=True)
    username = models.CharField(max_length=30)
    full_name = models.CharField(max_length=70)
    email = models.CharField(max_length=60)
    creation_date = models.DateField(auto_now_add=True)
    profile_img = models.CharField(max_length=60, null=True)
