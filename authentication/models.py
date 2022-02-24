from django.db import models


class Country(models.Model):
    name = models.CharField(max_length=50)
    iso = models.CharField(max_length=5)

    class Meta:
        db_table = "countries"


class Gender(models.Model):
    name = models.CharField(max_length=50)

    class Meta:
        db_table = "genders"


class User(models.Model):
    id = models.AutoField(primary_key=True, unique=True,)
    sub = models.CharField(max_length=120, unique=True)
    is_admin = models.BooleanField(default=False)
    nick_name = models.CharField(max_length=30)
    full_name = models.CharField(max_length=60)
    email = models.CharField(max_length=60)
    profile_image = models.TextField(null=True)
    strikes = models.IntegerField(default=0)
    creation_at = models.DateField(auto_now_add=True)
    country_id = models.ForeignKey(null=True, to=Country, on_delete=models.CASCADE)
    gender_id = models.ForeignKey(null=True, to=Gender, on_delete=models.CASCADE)

    class Meta:
        db_table = "users"
