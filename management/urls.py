from django.urls import path
from . import views

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

    # Forms
    path('create/user', views.user_creation_view, name='create-user'),
    path('create/bedspace', views.bedspace_creation_view, name='create-bedspace'),
    path('create/bedspacing', views.bedspacing_creation_view, name='create-bedspacing'),
    path('create/unit', views.unit_creation_view, name='create-unit'),
    path('create/residence', views.residence_creation_view, name='create-residence'),
    path('create/device', views.device_creation_view, name='create-device'),
    path('create/account', views.account_creation_view, name='create-account'),

    # Edit
]
