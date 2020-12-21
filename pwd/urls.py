
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path
from django.urls import include
# from . import views
# from authentication import views
# from userprofile import views
from django.conf.urls.static import static
from django.conf import settings
from . import views

urlpatterns = [
    path('', include('index.urls')),
    path('index/', include('index.urls')),
    path('index/index.html', include('index.urls')),
    path('index.html', include('index.urls')),
    
    path('actionPhishingWD', include('actionPhishingWD.urls')),
    
    path('userprofile/',include('userprofile.urls')),
    
    path('admin/', admin.site.urls),
    
    path('contact/', include('contact.urls')),
    path('contact.html', include('contact.urls')),
    
    path('about/', include('about.urls')),
    path('about.html', include('about.urls')),
    
        
    path('authentication/', include('authentication.urls')), #login,signup,resetPassword
    
    path('reset_password/', auth_views.PasswordResetView.as_view(template_name="authentication/resetPassword.html") , name="reset_password"),
    path('reset_password_sent/', auth_views.PasswordResetDoneView.as_view(template_name="authentication/emailsent.html"), name="password_reset_done"),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name="authentication/resetForm.html"), name="password_reset_confirm"),
    path('reset_password_complete/', auth_views.PasswordResetCompleteView.as_view(template_name="authentication/resetComplete.html"), name="password_reset_complete"),
    
    
]+static(settings.MEDIA_URL,document_root = settings.MEDIA_ROOT)
