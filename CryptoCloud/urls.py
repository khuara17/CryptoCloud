"""CryptoCloud URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static

from django.contrib import admin
from django.urls import path,include
from . import views

from login.views import userregister, user_login,admin_login,userlogin_check
urlpatterns = [
    path('', views.index, name="index"),
    path('admin/', admin.site.urls),
    path('admins/', include('admins.urls'), name="admins"),
    path('user/', include('user.urls'), name="user"),
    path('logout', views.logout, name="logout"),

    path('adminlogin/', admin_login, name='adminlogin'),
    path('userregistration/', userregister, name='userregistration'),
    path('userlogin/', user_login, name='userlogin'),
    path('userlogincheck', userlogin_check,name="userlogincheck"),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)