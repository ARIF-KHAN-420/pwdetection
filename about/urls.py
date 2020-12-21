from django.urls import path
from . import views

urlpatterns = [
    path('about.html',views.about,name='about'),       
    path('',views.about,name='about'),       
]