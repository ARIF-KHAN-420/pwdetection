from django.shortcuts import render
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.models import User
from authentication.models import profilePicture

from .form import ImageForm

# Create your views here.
def userprofile(request):
    propicture = profilePicture.objects.filter(username = request.user.username)
    for x in propicture:
        propictur = {'propic' : x, 'form' : ImageForm() }
    
    
    if request.method == 'POST':
        username = request.POST['username']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        email = request.POST['email']
        password = request.POST['password']
        
        if User.objects.filter(email = email).exists():
            user = authenticate(request,username = username, password = password)
        
            if user is not None:
                user.first_name = firstname
                user.last_name = lastname
                user.save()
                propictur['messeage'] = 'First Name and Last Name Changed,Email Exist'
            else:
                propictur['messeage'] =  'Wrong Password'
        else:
            user = authenticate(request,username = username, password = password)
        
            if user is not None:
                user.email = email
                user.first_name = firstname
                user.last_name = lastname
                user.save()
                propictur['messeage'] =  'Name and Email updated'
            else:
                propictur['messeage'] =  'Wrong Password'
                
        return render(request,'userprofile/usrProfile.html',propictur)
    return render(request,'userprofile/usrProfile.html',propictur)

def pictureUp(request):
    propictur = {}
    propicture = profilePicture.objects.filter(username = request.user.username)
    for x in propicture:
        propictur = {'propic' : x, 'form' : ImageForm() }
    
    if request.method == "POST":
        form=ImageForm(data=request.POST,files=request.FILES)
        if form.is_valid():
            form.save()
            obj=form.instance
            propictur = {'propic' : obj}
            propictur['messeage'] =  'Picture Updated'
            return render(request,'userprofile/usrProfile.html',propictur)
        else:
            propictur = {'messeage' : 'user Not found', 'form' : ImageForm()}
            return render(request,'userprofile/usrProfile.html',propictur)
    return render(request,'userprofile/usrProfile.html')