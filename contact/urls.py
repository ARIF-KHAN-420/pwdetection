from django.urls import path
from . import views

urlpatterns = [
    path('contact.html',views.contactFunction,name='contact'),       
    path('',views.contactFunction,name='contact'),       
    
]