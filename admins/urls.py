from django.urls import path
from . import views

urlpatterns = [
    path('home/',views.adminhome,name="adminhome"),
    path('usermanage/',views.usermanage,name="usermanage"),
    path('uploadlog/',views.uploadlog,name="uploadlog"),
    path('charts/',views.charts,name="charts"),
    path('user_activation/',views.user_activation,name="user_activation"),
]