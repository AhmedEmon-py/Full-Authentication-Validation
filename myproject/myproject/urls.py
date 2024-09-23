
from django.contrib import admin
from django.urls import path
from myproject.views import*

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', loginPage, name='loginPage'),
    path('signupPage/', signupPage, name='signupPage'),
    path('homepage/', homepage, name='homepage'),
    path('logoutPage/', logoutPage, name='logoutPage'),


]
