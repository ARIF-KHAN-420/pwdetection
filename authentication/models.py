from django.db import models
from jsonschema._validators import maxLength

# Create your models here.
class profilePicture(models.Model):
    username = models.CharField(max_length= 300,blank = False)
    propicture = models.ImageField(upload_to = 'userProfile/' ,blank= False)
    
    def __str__(self):
        return self.username
    