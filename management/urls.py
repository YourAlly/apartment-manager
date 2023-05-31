from django.urls import path
from . import views
from django.conf.urls.static import static

import apartment.settings as settings

urlpatterns = [
    path('', views.index, name='index'),
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),
    path('users', views.users_view, name='users'),
    path('users/<int:user_id>', views.user_view, name='user'),
    path('units', views.units_view, name='units'),
    path('units/<int:unit_id>', views.unit_view, name='unit'),
    path('bedspaces', views.bedspaces_view, name='bedspaces'),
    path('bedspaces/<int:bedspace_no>', views.bedspace_view, name='bedspace'),
    path('accounts', views.accounts_view, name='accounts'),
    path('devices', views.devices_view, name='devices'),

    # Forms
    path('create/user', views.user_creation_view, name='create-user'),
    path('create/bedspace', views.bedspace_creation_view, name='create-bedspace'),
    path('create/bedspacing', views.bedspacing_creation_view, name='create-bedspacing'),
    path('create/unit', views.unit_creation_view, name='create-unit'),
    path('create/unit-image',
         views.unit_image_creation_view, name='create-unit-image'),
    path('create/residence', views.residence_creation_view, name='create-residence'),
    path('create/resident', views.resident_creation_view, name='create-resident'),
    path('create/device', views.device_creation_view, name='create-device'),
    path('create/account', views.account_creation_view, name='create-account'),
    path('reset-password', views.password_reset_view, name='password-reset'),

    # Deactivation
    path('units/<int:unit_id>/deactivate',
         views.unit_deactivation_view, name='deactivate-unit'),
    path('bedspaces/<int:bed_no>/deactivate',
        views.bedspace_deactivation_view, name='deactivate-bedspace'),
    path('accounts/<int:account_id>/settle',
         views.account_settlement_view, name='settle-account'),

    # Edit
    path('users/<int:user_id>/edit', views.user_edit_view, name='edit-user'),
    path('units/<int:unit_id>/edit', views.unit_edit_view, name='edit-unit'),
    path('bedspaces/<int:bed_no>/edit', views.bedspace_edit_view, name='edit-bedspace'),
    path('accounts/<int:account_id>/edit', views.account_edit_view, name='edit-account'),
    path('devices/<int:device_id>/edit', views.device_edit_view, name='edit-device'),

    # Delete
    path('users/<int:user_id>/delete', views.user_deletion_view, name='delete-user'),
    path('units/<int:unit_id>/delete', views.unit_deletion_view, name='delete-unit'),
    path('resident/<int:resident_id>/delete',
         views.resident_deletion_view, name='delete-resident'),
    path('bedspaces/<int:bed_no>/delete',
         views.bedspace_deletion_view, name='delete-bedspace'),
    path('accounts/<int:account_id>/delete',
         views.account_deletion_view, name='delete-account'),
    path('devices/<int:device_id>/delete',
         views.device_deletion_view, name='delete-device'),
    path('unit-images/<int:unit_image_id>/delete',
         views.unit_image_deletion_view, name='delete-unit-image'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)