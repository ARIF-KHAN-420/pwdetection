from django.urls import path
# from django.urls import include
from . import views

urlpatterns = [
    # path('login.html',views.login,name='login'),
    
    path('',views.authlogin,name='login'),
    path('login.html',views.authlogin,name='login'),
    
    path('signup/',views.authsignup,name='signup'),
    path('signup.html',views.authsignup,name='signup'),
    
    path('resetPassword/',views.resetPassword,name='resetPassword'),
    path('resetPassword.html',views.resetPassword,name='resetPassword'),
    
    path('logout',views.userlogout,name='logout'),
        
] 