from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
# Create your models here.

class User(AbstractUser):
    is_tenant = models.BooleanField(default=False)

class Tenant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateField(default=timezone.now)
    date_left = models.DateField(blank=True, null=True)

class Unit(models.Model):
    name = models.CharField(max_length=64)
    details = models.TextField()
