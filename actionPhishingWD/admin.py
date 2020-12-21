from django.contrib import admin

# Register your models here.
from .models import phishing_site_list
from .models import Legitimate_site_list

admin.site.register(phishing_site_list)
admin.site.register(Legitimate_site_list)