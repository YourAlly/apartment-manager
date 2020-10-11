from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from apartment.settings import AUTH_USER_MODEL
from django.core.exceptions import ValidationError

from PIL import Image

# Create your models here.
class User(AbstractUser):
    contacts = models.CharField(max_length=64, blank=True, null=True)

    def is_tenant(self):
        return bool(self.residences.filter(is_active=True))

    def is_bedspacer(self):
        return bool(self.bedspacings.filter(is_active=True))

    def full_name(self):
        return ' '.join([self.first_name, self.last_name]
                ) if self.first_name or self.last_name else f'{self.username} (username)'


class Unit(models.Model):
    name = models.CharField(max_length=64, unique=True)
    cost = models.IntegerField(default=0)
    details = models.TextField(blank=True)
    is_available = models.BooleanField(default=True)

    def __str__(self):
        return f'{self.name}'

    def is_active(self):
        return bool(self.residences.filter(is_active=True))

    def current_user(self):
        if not self.is_active():
            return None
        
        return self.residences.filter(is_active=True).first().tenant
    

class Bedspace(models.Model):
    bed_number = models.IntegerField(unique=True)
    is_available = models.BooleanField(default=True)
    
    def __str__(self):
        return f'{self.bed_number}'

    def is_active(self):
        return bool(self.bedspacings.filter(is_active=True))

    def current_user(self):
        if not self.is_active():
            return None
        
        return self.bedspacings.filter(is_active=True).first().bedspacer
    

class Bedspacing(models.Model):
    bedspace = models.ForeignKey(Bedspace, on_delete=models.CASCADE,
            related_name='bedspacings')
    bedspacer = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE,
            related_name="bedspacings")
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    date_left = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return (self.bedspacer.full_name() or self.bedspacer.username
                ) + f' - {self.bedspace.bed_number}' 

    def clean(self):
        if self.bedspace.is_active() and self.is_active:
            raise ValidationError('The Selected bedspace is Already Active',
                code='invalid')
        
        if not self.bedspace.is_available:
            raise ValidationError('The Selected bedspace is Currently Unavailable',
                                  code='invalid')


class Residence(models.Model):
    tenant = models.ForeignKey(AUTH_USER_MODEL,
        on_delete=models.CASCADE, related_name='residences')
    unit = models.ForeignKey(Unit,
        on_delete=models.CASCADE, related_name='residences')
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    date_left = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return (self.tenant.full_name() or self.tenant.username
        ) + f' - {self.unit.name}'

    def clean(self):
        if self.unit.is_active() and self.is_active:
            raise ValidationError('The Selected Unit is Already Active',
                    code='invalid')
        
        if not self.unit.is_available:
            raise ValidationError('The Selected Unit is Currently Unavailable',
                                  code='invalid')


class Account(models.Model):
    name = models.CharField(max_length=64)
    notes = models.TextField(blank=True, null=True)
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE,
            related_name="accounts")
    amount = models.IntegerField(default=0)
    is_settled = models.BooleanField(default=False)
    date_added = models.DateTimeField(default=timezone.now)


class Device(models.Model):
    name = models.CharField(max_length=64)
    mac_address = models.CharField(max_length=64, unique=True)
    owner = models.ForeignKey(
        AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="devices")
    date_added = models.DateTimeField(default=timezone.now)


class Unit_Image(models.Model):
    unit = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name="images")
    image = models.ImageField(default='default.jpg', upload_to='unit_images')
