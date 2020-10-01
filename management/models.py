from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from apartment.settings import AUTH_USER_MODEL

# Create your models here.
class User(AbstractUser):
    contacts = models.CharField(max_length=64, blank=True, null=True)
    def is_tenant(self):
        query = self.residences.filter(is_active=True)
        return bool(query)

    def is_bedspacer(self):
        query = self.bedspacings.filter(is_active=True)
        return bool(query)

    def full_name(self):
        return ' '.join([self.first_name, self.last_name])


class Unit(models.Model):
    name = models.CharField(max_length=64)
    cost = models.IntegerField(default=0)
    details = models.TextField()

    def __str__(self):
        return f'{self.name}'

    def is_active(self):
        query = self.residences.filter(is_active=True)
        return bool(query)


class Bedspace(models.Model):
    bed_no = models.IntegerField()
    is_available = models.BooleanField()
    
    def __str__(self):
        return f'{self.bed_no}'

    def is_active(self):
        query = self.bedspacings.filter(is_active=True)
        return bool(query)


class Bedspacing(models.Model):
    bedspace = models.ForeignKey(Bedspace, on_delete=models.CASCADE, related_name='bedspacings')
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="bedspacings")
    is_active = models.BooleanField(default=True)
    date_joined = models.DateField(default=timezone.now)
    date_left = models.DateField(blank=True, null=True)

    def __str__(self):
        return (self.user.full_name() if self.user.full_name() else self.user.username) + self.bedspace.bed_no 


class Residence(models.Model):
    tenant = models.ForeignKey(AUTH_USER_MODEL,
        on_delete=models.CASCADE, related_name='residences')
    unit = models.ForeignKey(Unit,
        on_delete=models.CASCADE, related_name='residences')
    is_active = models.BooleanField(default=True)
    date_joined = models.DateField(default=timezone.now)
    date_left = models.DateField(blank=True, null=True)

    def __str__(self):
        return f'{self.tenant.full_name() if self.tenant.full_name() else self.tenant.username} - {self.unit.name}'


class Account(models.Model):
    name = models.CharField(max_length=64)
    notes = models.TextField(blank=True, null=True)
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="accounts")
    amount = models.IntegerField(default=0)
    is_settled = models.BooleanField(default=False)


class Device(models.Model):
    name = models.CharField(max_length=64)
    mac_address = models.CharField(max_length=64)
    owner = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="devices")
