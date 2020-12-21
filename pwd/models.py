from django.db import models

# Create your models here.

class userSignup(models.Model):
    
    first_name = models.CharField(max_length=100,blank=False) 
    last_name = models.CharField(max_length=100,blank=False)  
    email = models.EmailField(max_length=200,blank=False)     
    country = models.CharField(max_length=100,blank=False)    
    password = models.CharField(max_length=600,blank=False)    
    def __str__(self):
        return self.email