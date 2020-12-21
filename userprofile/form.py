from django import forms
from authentication.models import profilePicture

class ImageForm(forms.ModelForm):
    class Meta:
        model=profilePicture
        fields=("username","propicture")