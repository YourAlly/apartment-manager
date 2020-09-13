from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# Create your models here.
class User(AbstractUser):
    is_tenant = models.BooleanField(default=False, help_text='Tenant Status')


class Unit(models.Model):
    name = models.CharField(max_length=64)
    cost = models.IntegerField(default=0)
    details = models.TextField()

    def __str__(self):
        return f'{self.name}'

class Tenant(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, primary_key=True)

    def __str__(self):
        return f'{self.user.first_name} {self.user.last_name}' if self.user.first_name or self.user.last_name else self.user.username
    
class Residence(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='units')
    unit = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name='residents')
    is_active = models.BooleanField(default=True)
    date_joined = models.DateField(default=timezone.now)
    date_left = models.DateField(blank=True, null=True)

