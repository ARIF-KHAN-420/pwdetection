from django.urls import path
from . import views

urlpatterns = [
    path('',views.userprofile,name='userprofile'),
    path('usrProfile.html',views.userprofile,name='userprofile'),
    path('pictureUpdate',views.pictureUp,name='pictureUpdate'),
    
    
]