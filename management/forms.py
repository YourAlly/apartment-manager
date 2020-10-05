from django.contrib.auth.forms import UserCreationForm
from .models import User, Residence, Account, Unit, Device, Bedspace, Bedspacing
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


class BedspaceCreationForm(forms.ModelForm):
    class Meta:
        model = Bedspace
        fields = ['bed_number']


class BedspacingCreationForm(forms.ModelForm):
    class Meta:
        model = Bedspacing
        fields = ['bedspace', 'bedspacer']


class UnitCreationForm(forms.ModelForm):
    class Meta:
        model = Unit
        fields = ['name', 'cost', 'details']


class ResidenceCreationForm(forms.ModelForm):
    class Meta:
        model = Residence
        fields = ['tenant', 'unit']


class AccountCreationForm(forms.ModelForm):
    class Meta:
        model = Account
        fields = ['name', 'notes', 'user', 'amount']


class DeviceCreationForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ['name', 'mac_address', 'owner']


class ConfirmationForm(forms.Form):
    confirm = forms.BooleanField(required=True, label='Are you sure about this action?')