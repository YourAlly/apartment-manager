from django.shortcuts import render, redirect
from .models import User, Residence, Account, Unit, Device, Bedspace, Bedspacing, Unit_Image
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage

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
        unsettled_accounts = request.user.accounts.filter(is_settled=False)
        devices = request.user.devices.all()

        active_residences = request.user.residences.filter(is_active=True)
        active_bedspacings = request.user.bedpacings.filter(is_active=True)

        inactive_residences = request.user.residences.filter(is_active=False)
        inactive_bedspacings = request.user.bedpacings.filter(is_active=False)
        
        return render(request, 'management/user-index.html',{
            'active_units': active_units,
            'active_residences': active_residences,
            'active_bedspaces': active_bedspaces,
            'active_bedspacings': active_bedspacings,
            'unsettled_accounts': unsettled_accounts,
            'devices': devices
        })


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
def user_view(request, user_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    user = User.objects.get(pk=user_id)
    active_residences = user.residences.filter(is_active=True)
    active_bedspacings = user.bedspacings.filter(is_active=True)
    unsettled_accounts = user.accounts.filter(is_settled=False)
    registered_devices = user.devices.all()

    return render(request, 'management/admin/user.html', {
        'user': user,
        'active_residences': active_residences,
        'active_bedspacings': active_bedspacings,
        'unsettled_accounts': unsettled_accounts,
        'registered_devices': registered_devices
    })


@login_required
def units_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    all_units = Unit.objects.all()
    page = request.GET.get('page', 1)
    paginator = Paginator(all_units, 6)

    try:
        units = paginator.page(page)
    except PageNotAnInteger:
        units = paginator.page(1)
    except EmptyPage:
        units = paginator.page(paginator.num_pages)

    return render(request, 'management/admin/units.html', {
        'units': units
    })


@login_required
def unit_view(request, unit_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        unit = Unit.objects.get(pk=unit_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    if unit.is_active():
        unsettled_accounts = unit.current_user().accounts.filter(is_settled=False)
    else:
        unsettled_accounts = None

    inactive_residences = unit.residences.filter(is_active=False)

    return render(request, 'management/admin/unit.html', {
        'unit': unit,
        'inactive_residences': inactive_residences,
        'unsettled_accounts': unsettled_accounts or None
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
def bedspace_view(request, bedspace_no):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        bedspace = Bedspace.objects.get(bed_number=bedspace_no)
    except:
        return render(request, 'management/admin/admin-404.html')

    if bedspace.is_active():
        unsettled_accounts = bedspace.current_user().accounts.filter(is_settled=False)
    else:
        unsettled_accounts = None

    inactive_bedspacings = bedspace.bedspacings.filter(is_active=False)

    return render(request, 'management/admin/bedspace.html', {
        'bedspace': bedspace,
        'inactive_bedspacings': inactive_bedspacings,
        'unsettled_accounts': unsettled_accounts
    })


@login_required
def accounts_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    settled_accounts = Account.objects.filter(is_settled=True)
    unsettled_accounts = Account.objects.filter(is_settled=False)

    return render(request, 'management/admin/accounts.html', {
        'settled_accounts': settled_accounts,
        'unsettled_accounts': unsettled_accounts
    })


@login_required
def devices_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    all_devices = Device.objects.all()

    return render(request, 'management/admin/devices.html', {
        'all_devices': all_devices,
    })


# Deactivation Views
@login_required
def bedspace_deactivation_view(request, bed_no):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        bedspace = Bedspace.objects.get(bed_number=bed_no)
    except:
        return render(request, 'management/admin/admin-404.html')
    
    if not bedspace.is_active() or not bedspace.is_available:
        messages.warning(request, 'The bedspace is currently inactive or unavailable')
        return redirect('bedspace', bed_no)

    else:
        if request.method == 'POST':
            confirmation = forms.ConfirmationForm(request.POST)
            if confirmation.is_valid() and confirmation.cleaned_data['confirm']:
                bedspacing = bedspace.bedspacings.filter(is_active=True).first()
                bedspacing.is_active = False
                bedspacing.date_left = timezone.now()
                bedspacing.save()

                bedspacer = bedspacing.bedspacer.full_name()
                messages.success(request, f'{bedspacer} is no longer a bedspacer of this bedspace')

            return redirect('bedspace', bed_no)

        else:
            return render(request, 'management/admin/form.html',{
                'form_title': 'Confirmation Form',
                'form': forms.ConfirmationForm()

            })


@login_required
def unit_deactivation_view(request, unit_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        unit = Unit.objects.get(pk=unit_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    if not unit.is_active() or not unit.is_available:
        messages.warning(
            request, 'The unit is currently inactive or unavailable')
        return redirect('unit', unit_id)

    else:
        if request.method == 'POST':
            confirmation = forms.ConfirmationForm(request.POST)
            if confirmation.is_valid() and confirmation.cleaned_data['confirm']:
                residence = unit.residences.filter(is_active=True).first()
                residence.is_active = False
                residence.date_left = timezone.now()
                residence.save()

                tenant = residence.tenant.full_name()
                messages.success(request, f'{tenant} is no longer a tenant of this unit')

            return redirect('unit', unit_id)

        else:
            return render(request, 'management/admin/form.html', {
                'form_title': 'Confirmation Form',
                'form': forms.ConfirmationForm()

            })

# I consider it to be similar to deactivation
@login_required
def account_settlement_view(request, account_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        account = Account.objects.get(pk=account_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    if account.is_settled:
        messages.warning(
            request, 'The account is already settled')
        return redirect('accounts')

    else:
        if request.method == 'POST':
            confirmation = forms.ConfirmationForm(request.POST)
            if confirmation.is_valid() and confirmation.cleaned_data['confirm']:
                account.is_settled = True
                account.save()
                messages.success(
                    request, f'The account is now settled')

            return redirect('accounts')

        else:
            return render(request, 'management/admin/form.html', {
                'form_title': 'Confirmation Form',
                'form': forms.ConfirmationForm()

            })


# Form Views
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
            residence = form.save()
            messages.success(request, f'{ residence.tenant.full_name() } Registered!')
            return redirect('unit', residence.unit.id)

    else:
        unit_id = request.GET.get('unit_id')
        if unit_id:
            try:
                unit = Unit.objects.get(pk=unit_id)
            except:
                messages.warning(request, 'Unit not found')
                form = forms.ResidenceCreationForm()
            else: 
                form = forms.ResidenceCreationForm(initial={'unit': unit})
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
            bedspacing = form.save()
            messages.success(request, 'Bedspacing Created!')
            return redirect('bedspace', bedspacing.bedspace.id)

    else:
        bed_no = request.GET.get('bed_no')
        if bed_no:
            try:
                bedspace = Bedspace.objects.get(bed_number=bed_no)
            except:
                messages.warning(request, 'Bedspace not found')
                form = forms.BedspacingCreationForm()
            else:
                form = forms.BedspacingCreationForm(initial={'bedspace': bedspace})
        
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
        user_id = request.GET.get('user_id')
        if user_id:
            try:
                user = User.objects.get(pk=user_id)
            except:
                messages.warning(request, 'User not found')
                form = forms.AccountCreationForm()
            else:
                form = forms.AccountCreationForm(initial={'user': user})

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
        user_id = request.GET.get('user_id')
        if user_id:
            try:
                user = User.objects.get(pk=user_id)
            except:
                messages.warning(request, 'User not found')
                form = forms.DeviceCreationForm()
            else:
                form = forms.DeviceCreationForm(initial={'owner': user})

        else:
            form = forms.DeviceCreationForm()

    return render(request, 'management/admin/form.html', {
        'form_title': 'Device Creation Form',
        'form': form
    })


@login_required
def unit_image_creation_view(request):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    if request.method == 'POST':
        form = forms.UnitImageCreationForm(request.POST, request.FILES)
        if form.is_valid():
            image = form.save()
            messages.success(request, 'Image Uploaded!')
            return redirect('unit', image.unit.id)

    else:
        unit_id = request.GET.get('unit_id')
        if unit_id:
            try:
                unit = Unit.objects.get(pk=unit_id)
            except:
                messages.warning(request, 'Unit not found')
                form = forms.UnitImageCreationForm()
            else:
                form = forms.UnitImageCreationForm(initial={'unit': unit})
        else:
            form = forms.UnitImageCreationForm()

    return render(request, 'management/admin/form.html', {
        'form_title': 'Unit Image Upload Form',
        'multipart': True,
        'form': form
    })


# Edit Views
@login_required
def user_edit_view(request, user_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        target = User.objects.get(pk=user_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    if request.method == 'POST':
        form = forms.UserEditForm(request.POST, instance=target)
        if form.is_valid():
            form.save()
            messages.success(request, 'User Edited!')
            return redirect('user', user_id)

    else:
        form = forms.UserEditForm(instance=target)

    return render(request, 'management/admin/form.html', {
        'form_title': 'User Edit Form',
        'form': form
    })


@login_required
def unit_edit_view(request, unit_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        target = Unit.objects.get(pk=unit_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    if request.method == 'POST':
        form = forms.UnitCreationForm(request.POST, instance=target)
        if form.is_valid():
            form.save()
            messages.success(request, 'Unit Edited!')
            return redirect('unit', unit_id)

    else:
        form = forms.UnitCreationForm(instance=target)

    return render(request, 'management/admin/form.html', {
        'form_title': 'Unit Edit Form',
        'form': form
    })


@login_required
def bedspace_edit_view(request, bed_no):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        target = Bedspace.objects.get(pk=bed_no)
    except:
        return render(request, 'management/admin/admin-404.html')

    if request.method == 'POST':
        form = forms.BedspaceCreationForm(request.POST, instance=target)
        if form.is_valid():
            form.save()
            messages.success(request, 'Bedspace Edited!')
            return redirect('bedspace', bed_no)

    else:
        form = forms.BedspaceCreationForm(instance=target)

    return render(request, 'management/admin/form.html', {
        'form_title': 'Account Edit Form',
        'form': form
    })


@login_required
def account_edit_view(request, account_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        target = Account.objects.get(pk=account_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    if request.method == 'POST':
        form = forms.AccountCreationForm(request.POST, instance=target)
        if form.is_valid():
            form.save()
            messages.success(request, 'Account Edited!')
            return redirect('account')

    else:
        form = forms.AccountCreationForm(instance=target)

    return render(request, 'management/admin/form.html', {
        'form_title': 'Account Edit Form',
        'form': form
    })


@login_required
def device_edit_view(request, device_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        target = Device.objects.get(pk=device_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    if request.method == 'POST':
        form = forms.DeviceCreationForm(request.POST, instance=target)
        if form.is_valid():
            form.save()
            messages.success(request, 'Device Edited!')
            return redirect('devices')

    else:
        form = forms.DeviceCreationForm(instance=target)

    return render(request, 'management/admin/form.html', {
        'form_title': 'Device Edit Form',
        'form': form
    })


# Delete Views
@login_required
def user_deletion_view(request, user_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        user = User.objects.get(pk=user_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    else:
        if request.method == 'POST':
            confirmation = forms.ConfirmationForm(request.POST)
            if confirmation.is_valid() and confirmation.cleaned_data['confirm']:
                user.delete()
                messages.success(
                    request, f'The User is now deleted')

            return redirect('users')

        else:
            messages.warning(request, f'User { user.username } will be deleted')
            return render(request, 'management/admin/form.html', {
                'form_title': 'Confirmation Form',
                'form': forms.ConfirmationForm()

            })


@login_required
def unit_deletion_view(request, unit_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        unit = Unit.objects.get(pk=unit_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    else:
        if request.method == 'POST':
            confirmation = forms.ConfirmationForm(request.POST)
            if confirmation.is_valid() and confirmation.cleaned_data['confirm']:
                unit.delete()
                messages.success(
                    request, f'The User is now deleted')

            return redirect('users')

        else:
            messages.warning(request, f'Unit { unit.name } will be deleted')
            return render(request, 'management/admin/form.html', {
                'form_title': 'Confirmation Form',
                'form': forms.ConfirmationForm()

            })


@login_required
def bedspace_deletion_view(request, bed_no):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        bedspace = Bedspace.objects.get(pk=bed_no)
    except:
        return render(request, 'management/admin/admin-404.html')

    else:
        if request.method == 'POST':
            confirmation = forms.ConfirmationForm(request.POST)
            if confirmation.is_valid() and confirmation.cleaned_data['confirm']:
                bedspace.delete()
                messages.success(
                    request, f'The User is now deleted')

            return redirect('users')

        else:
            messages.warning(request, f'Bed number { bedspace.bed_number } will be deleted')
            return render(request, 'management/admin/form.html', {
                'form_title': 'Confirmation Form',
                'form': forms.ConfirmationForm()

            })


@login_required
def account_deletion_view(request, account_id):
    try:
        account = Account.objects.get(pk=account_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    else:
        if request.method == 'POST':
            confirmation = forms.ConfirmationForm(request.POST)
            if confirmation.is_valid() and confirmation.cleaned_data['confirm']:
                account.delete()
                messages.success(
                    request, f'The User is now deleted')

            return redirect('user', account.user.id)

        else:
            messages.warning(request, f'{ account.name } will be deleted')
            return render(request, 'management/admin/form.html', {
                'form_title': 'Confirmation Form',
                'form': forms.ConfirmationForm()

            })


@login_required
def device_deletion_view(request, device_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        device = Device.objects.get(pk=device_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    else:
        if request.method == 'POST':
            confirmation = forms.ConfirmationForm(request.POST)
            if confirmation.is_valid() and confirmation.cleaned_data['confirm']:
                device.delete()
                messages.success(
                    request, f'The Device is now deleted')

            return redirect('user', device.owner.id)

        else:
            messages.warning(request, f'{ device.name } will be deleted')
            return render(request, 'management/admin/form.html', {
                'form_title': 'Confirmation Form',
                'form': forms.ConfirmationForm()

            })


@login_required
def unit_image_deletion_view(request, unit_image_id):
    if not request.user.is_superuser:
        messages.warning(request, 'You are not allowed to access this page')
        return redirect('index')

    try:
        unit_image = Unit_Image.objects.get(pk=unit_image_id)
    except:
        return render(request, 'management/admin/admin-404.html')

    else:
        if request.method == 'POST':
            confirmation = forms.ConfirmationForm(request.POST)
            if confirmation.is_valid() and confirmation.cleaned_data['confirm']:
                unit_image.delete()
                messages.success(
                    request, f'The unit_image is now deleted')

            return redirect('unit', unit_image.unit.id)

        else:
            messages.warning(request, f'Unit_Image_{ unit_image.id } will be deleted')
            return render(request, 'management/admin/form.html', {
                'form_title': 'Confirmation Form',
                'form': forms.ConfirmationForm()

            })
