from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.login_view, name='login_view'),
    path('register', views.register_view, name='register_view'),
    path('logout', views.logout_view, name='logout_view'),
    path('data-storage', views.data_storage, name='data_storage'),
    path('view-data', views.view_data, name='view_data'),
]
