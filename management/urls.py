from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),
    path('units', views.units_view, name='units'),
    path('bedspaces', views.bedspaces_view, name='bedspaces'),
]