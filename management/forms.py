from django.contrib.auth.forms import UserCreationForm
from .models import User, Residence, Account, Unit, Device, Bedspace, Bedspacing, Resident, Unit_Image
from django import forms


class RegistrationForm(UserCreationForm):
    class Meta:
        model = User
        fields = [
            'username',
            'password1',
            'password2',
            'first_name',
            'last_name',
            'contacts'
        ]


class UserEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = [
            'first_name',
            'last_name',
            'contacts',
        ]


class BedspaceCreationForm(forms.ModelForm):
    class Meta:
        model = Bedspace
        fields = ['bed_number', 'is_available']


class BedspacingCreationForm(forms.ModelForm):
    class Meta:
        model = Bedspacing
        fields = ['bedspace', 'bedspacer']


class UnitCreationForm(forms.ModelForm):
    class Meta:
        model = Unit
        fields = ['name', 'cost', 'details', 'is_available']


class UnitImageCreationForm(forms.ModelForm):
    class Meta:
        model = Unit_Image
        fields = ['unit', 'image']

class ResidenceCreationForm(forms.ModelForm):
    class Meta:
        model = Residence
        fields = ['unit', 'tenant']


class AccountCreationForm(forms.ModelForm):
    class Meta:
        model = Account
        fields = ['name', 'notes', 'user', 'amount']


class DeviceCreationForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ['name', 'mac_address', 'owner']


class ResidentCreationForm(forms.ModelForm):
    class Meta:
        model = Resident
        fields = ['unit', 'name']


class ConfirmationForm(forms.Form):
    confirm = forms.BooleanField(required=False, label='Are you sure about this action?')


class PasswordResetForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput)
    new_password = forms.CharField(widget=forms.PasswordInput)
    confirmation = forms.CharField(widget=forms.PasswordInput)
