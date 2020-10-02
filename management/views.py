from django.shortcuts import render, redirect

from .models import User, Residence, Account, Unit, Device, Bedspace, Bedspacing
import apartment.settings
import requests
from datetime import timedelta, datetime
from django.utils import timezone
from django.db.models import Q
from django.contrib import messages
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.core.paginator import Paginator
from django import forms
from django.http import HttpResponse


class UserCreationForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'password', 'first_name', 'last_name']


class BedspaceCreationForm(forms.ModelForm):
    class Meta:
        model = Bedspace
        fields = ['bed_number']


class BedspacingCreationForm(forms.ModelForm):
    class Meta:
        model = Bedspacing
        fields = ['bedspace', 'user']


class UnitCreationForm(forms.ModelForm):
    class Meta:
        model = Unit
        fields = ['name', 'cost', 'details']


class AccountCreationForm(forms.ModelForm):
    class Meta:
        model = Account
        fields = ['name', 'notes', 'user', 'amount']


class DeviceCreationForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ['name', 'mac_address', 'owner']


# Create your views here.
@login_required
def index(request):
    if request.user.is_superuser:
        active_units = Residence.objects.filter(
            is_active=True)
        active_bedspaces = Bedspacing.objects.filter(is_active=True).order_by('bedspace')
        
        return render(request, 'management/admin/admin-index.html', {
            'active_units': active_units,
            'active_bedspaces': active_bedspaces,
        })
    else:
        return render(request, 'management/user-index.html')


def login_view(request):
    """
        Login Page
    """
    if request.method == "POST":
        # Attempt to sign user in
        username = request.POST.get("username")
        password = request.POST.get("password")

        recaptcha_response = request.POST.get('g-recaptcha-response')

        data = {
            'secret': apartment.settings.GOOGLE_RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        r = requests.post(
            'https://www.google.com/recaptcha/api/siteverify', data=data)
        result = r.json()
        ''' End reCAPTCHA validation '''

        if result['success']:
            user = authenticate(request, username=username, password=password)

        # Check if authentication successful
            if user is not None:
                login(request, user)
                messages.info(
                    request, 'STILL IN DEVELOPMENT: PLEASE FIND AS MANY BUGS AS POSSIBLE')
                return redirect('index')
            else:
                messages.warning(request, 'Invalid username or password')
        else:
            messages.warning(request, 'Invalid Captcha')

    return render(request, "management/login.html", {})


@login_required
def logout_view(request):
    """
        Logs the user out
    """
    logout(request)
    return redirect('login')


@login_required
def bedspaces_view(request):
    bedspaces = Bedspace.objects.all()

    return render(request, 'management/admin/bedspaces.html', {
        'bedspaces': bedspaces
    })


@login_required
def units_view(request):
    units = Unit.objects.all()
    return render(request, 'management/admin/units.html', {
        'units': units
    })