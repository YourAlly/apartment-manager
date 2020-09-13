from django.contrib import admin
from .models import User, Tenant, Unit, Residence
from django.contrib.auth.admin import UserAdmin

admin.site.site_header = 'Admin Panel'
admin.site.site_title = 'Admin page'


class ResidenceAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'unit', 'date_joined', 'is_active',)
    search_fields = ('tenant', 'unit',)
    list_filter = ('is_active',)


# Register your models here.

@admin.register(User)
class CustomUserModelAdmin(UserAdmin):
    fieldsets = (
        (None, {
            "fields": (
                'username',
                'password',
                'first_name',
                'last_name',
                'is_tenant',
                'is_staff',
                'is_active',
                'is_superuser',
                'last_login',
                'date_joined',
            ),
        }),
    )
    
    add_fieldsets = (
        (None, {
            "fields": (
                'username',
                'password',
                'first_name',
                'last_name',
                'is_tenant',
            ),
        }),
    )
    
    list_display = ('username', 'first_name', 'last_name', 'is_tenant')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    list_filter = ('is_tenant',)

admin.site.register(Tenant)
admin.site.register(Unit)
admin.site.register(Residence, ResidenceAdmin)
