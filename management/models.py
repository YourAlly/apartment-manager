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
        return ' '.join([self.first_name, self.last_name]) if self.first_name or self.last_name else None


class Unit(models.Model):
    name = models.CharField(max_length=64)
    cost = models.IntegerField(default=0)
    details = models.TextField()

    def __str__(self):
        return f'{self.name}'

    def is_active(self):
        query = self.residences.filter(is_active=True)
        return bool(query)

    def current_user(self):
        if not self.is_active:
            return None
        query = self.residences.filter(is_active=True).first()
        if query:
            return query.tenant.full_name()
    
    def current_user_id(self):
        if not self.is_active:
            return None
        query = self.residences.filter(is_active=True).first()
        if query:
            return query.tenant.id


class Bedspace(models.Model):
    bed_number = models.IntegerField(unique=True)
    is_available = models.BooleanField(default=True)
    
    def __str__(self):
        return f'{self.bed_number}'

    def is_active(self):
        query = self.bedspacings.filter(is_active=True)
        return bool(query)

    def current_user(self):
        if not is_active:
            return None
        query = self.bedspacings.filter(is_active=True)
        if query:
            return query.user.full_name()
    
    def current_user_id(self):
        if not is_active:
            return None
        query = self.bedspacings.filter(is_active=True)
        if query:
            return query.user.id

class Bedspacing(models.Model):
    bedspace = models.ForeignKey(Bedspace, on_delete=models.CASCADE, related_name='bedspacings')
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="bedspacings")
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    date_left = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return (self.user.full_name() if self.user.full_name() else self.user.username) + f'{self.bedspace.bed_number}' 


class Residence(models.Model):
    tenant = models.ForeignKey(AUTH_USER_MODEL,
        on_delete=models.CASCADE, related_name='residences')
    unit = models.ForeignKey(Unit,
        on_delete=models.CASCADE, related_name='residences')
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    date_left = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f'{self.tenant.full_name() if self.tenant.full_name() else self.tenant.username} - {self.unit.name}'


class Account(models.Model):
    name = models.CharField(max_length=64)
    notes = models.TextField(blank=True, null=True)
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="accounts")
    amount = models.IntegerField(default=0)
    is_settled = models.BooleanField(default=False)
    date_added = models.DateTimeField(default=timezone.now)


class Device(models.Model):
    name = models.CharField(max_length=64)
    mac_address = models.CharField(max_length=64)
    owner = models.ForeignKey(
        AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="devices")
    date_added = models.DateTimeField(default=timezone.now)
