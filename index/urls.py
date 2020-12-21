from django.urls import path
# from django.urls import include
from . import views

urlpatterns = [
    path('index.html',views.index,name='index'),
    path('',views.index,name='index'),
    
    
        
]