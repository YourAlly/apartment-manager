from django.contrib import admin
from .models import User, Unit, Residence, Bedspace, Account, Device, Resident, Bedspacing, Unit_Image
from django.contrib.auth.admin import UserAdmin

admin.site.site_header = 'Admin Panel'
admin.site.site_title = 'Admin page'


class ResidenceAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'unit', 'date_joined', 'is_active',)
    search_fields = ('tenant', 'unit',)
    list_filter = ('is_active',)


class BedspaceAdmin(admin.ModelAdmin):
    list_display = ('bed_number', 'is_active', 'is_available')


class UnitAdmin(admin.ModelAdmin):
    list_display = ('name', 'cost', 'is_active')
    search_fields = ('name',)


class AccountAdmin(admin.ModelAdmin):
    list_display = ('user', 'amount',)
    list_filter = ('is_settled',)


class DeviceAdmin(admin.ModelAdmin):
    list_display = ('name', 'mac_address', 'owner',)


class BedspacingAdmin(admin.ModelAdmin):
    list_display = ('bedspacer', 'date_joined', 'is_active', 'bedspace')
    search_fields = ('bedspacer', 'bedspace')
    list_filter = ('is_active',)


class CustomUserModelAdmin(UserAdmin):
    fieldsets = (
        (None, {
            "fields": (
                'username',
                'password',
            ),
        }),

        ('Personal Info', {
            'fields': (
                'first_name',
                'last_name',
                'contacts'
            ),
        }),

        ('Permissions', {
            'fields': (
                'is_active',
                'is_staff',
                'is_superuser',
                'groups',
                'user_permissions'
            ),
            'classes': (
                'collapse',
            )
        }),

        ('Important Dates', {
            "fields": (
                'last_login',
                'date_joined',
            ),
            'classes': (
                'collapse',
            )
        }),

    )

    add_fieldsets = (
        (None, {
            "fields": (
                'username',
                'password1',
                'password2'
            ),
        }),
        ('Details', {
            "fields": (
                'first_name',
                'last_name',
                'contacts'
            ),
        }),
    )

    list_display = ('username', 'first_name', 'last_name', 'is_tenant', 'is_bedspacer')
    search_fields = ('username', 'first_name', 'last_name', 'email')


# Register your models here.
admin.site.register(User, CustomUserModelAdmin)
admin.site.register(Bedspace, BedspaceAdmin)
admin.site.register(Bedspacing, BedspacingAdmin)
admin.site.register(Unit, UnitAdmin)
admin.site.register(Residence, ResidenceAdmin)
admin.site.register(Account, AccountAdmin)
admin.site.register(Device, DeviceAdmin)
admin.site.register(Unit_Image)
admin.site.register(Resident)