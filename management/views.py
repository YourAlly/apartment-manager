from django.shortcuts import render, redirect
from .models import User, Residence, Account, Unit, Device, Bedspace, Bedspacing
from django.utils import timezone
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.core.paginator import Paginator
import management.forms as forms
import apartment.settings
import requests


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
    logout(request)
    return redirect('login')


@login_required
def users_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    users = User.objects.exclude(is_superuser=True).exclude(is_staff=True)
    return render(request, 'management/admin/tenants_and_bedspacers.html', {
        'users': users
    })


@login_required
def units_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    units = Unit.objects.all()
    return render(request, 'management/admin/units.html', {
        'units': units
    })


@login_required
def bedspaces_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    bedspaces = Bedspace.objects.all().order_by('bed_number')

    return render(request, 'management/admin/bedspaces.html', {
        'bedspaces': bedspaces
    })


@login_required
def user_view(request, user_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    user = User.objects.get(pk=user_id)
    active_residences = user.residences.filter(is_active=True)
    active_bedspaces = user.bedspacings.filter(is_active=True)
    unsettled_accounts = user.accounts.filter(is_settled=False)
    registered_devices = user.devices.all()

    return render(request, 'management/admin/user.html', {
        'user': user,
        'active_residences': active_residences,
        'active_bedspacings': active_bedspaces,
        'unsettled_accounts': unsettled_accounts,
        'registered_devices': registered_devices
    })


@login_required
def unit_view(request, unit_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    unit = Unit.objects.get(pk=unit_id)


@login_required
def user_creation_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    if request.method == 'POST':
        form = forms.RegistrationForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(request, 'User Created!')
            return redirect('index')

    else:
        form = forms.RegistrationForm()

    return render(request, 'management/admin/form.html', {
        'form_title': 'User Creation Form',
        'form': form
    })


@login_required
def unit_creation_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    if request.method == 'POST':
        form = forms.UnitCreationForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(request, 'Unit Created!')
            return redirect('index')

    else:
        form = forms.UnitCreationForm()

    return render(request, 'management/admin/form.html', {
        'form_title': 'Unit Creation Form',
        'form': form
    })


@login_required
def residence_creation_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    if request.method == 'POST':
        form = forms.ResidenceCreationForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(request, 'Residence Created!')
            return redirect('index')

    else:
        form = forms.ResidenceCreationForm()

    return render(request, 'management/admin/form.html', {
        'form_title': 'Residence Creation Form',
        'form': form
    })


@login_required
def bedspace_creation_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    if request.method == 'POST':
        form = forms.BedspaceCreationForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(request, 'Bedspace Created!')
            return redirect('bedspaces')

    else:
        form = forms.BedspaceCreationForm()

    return render(request, 'management/admin/form.html', {
        'form_title': 'Bedspace Creation Form',
        'form': form
    })


@login_required
def bedspacing_creation_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    if request.method == 'POST':
        form = forms.BedspacingCreationForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(request, 'Bedspacing Created!')
            return redirect('index')

    else:
        form = forms.BedspacingCreationForm()

    return render(request, 'management/admin/form.html', {
        'form_title': 'Bedspacing Creation Form',
        'form': form
    })


@login_required
def account_creation_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    if request.method == 'POST':
        form = forms.AccountCreationForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(request, 'Account Created!')
            return redirect('index')

    else:
        form = forms.AccountCreationForm()

    return render(request, 'management/admin/form.html', {
        'form_title': 'Account Creation Form',
        'form': form
    })


@login_required
def device_creation_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    if request.method == 'POST':
        form = forms.DeviceCreationForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(request, 'Device Created!')
            return redirect('index')

    else:
        form = forms.DeviceCreationForm()

    return render(request, 'management/admin/form.html', {
        'form_title': 'Device Creation Form',
        'form': form
    })


@login_required
def unit_view(request, unit_id):
    try:
        unit = Unit.objects.get(pk=unit_id)
    except:
        return render(request, 'management/admin/admin-404.html')
        
    inactive_residences = unit.residences.filter(is_active=False)
    return render(request, 'management/admin/unit.html', {
        'unit': unit,
        'inactive_residences': inactive_residences
        })