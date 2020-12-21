from django.db import models

# Create your models here.
class phishing_site_list(models.Model):
    link =  models.CharField(max_length= 500,blank = False)
    
    def __str__(self):
        return self.link
    
class Legitimate_site_list(models.Model):
    link =  models.CharField(max_length= 500,blank = False)
    
    def __str__(self):
        return self.link