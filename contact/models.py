from django.db import models

# Create your models here.
class contact(models.Model):
    username = models.CharField(max_length= 300,blank = False)
    first_name = models.CharField(max_length= 300,blank = False)
    last_name = models.CharField(max_length= 300,blank = False)
    email = models.EmailField(max_length= 300,blank = False)
    message = models.CharField(max_length= 2000,blank = False)
    
    
    def __str__(self):
        return self.email
    