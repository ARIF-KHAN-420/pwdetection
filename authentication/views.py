from django.shortcuts import render,redirect
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.models import User
from .models import profilePicture

# Create your views here.
def authsignup(request):
    regFailed = {}
    if request.method == 'POST':
        username = request.POST['username']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password == confirm_password:
            if User.objects.filter(username= username).exists():
                regFailed = {'regF' :' user Already Exists '}
            elif User.objects.filter(email = email).exists():
                regFailed = {'regF' :' Email Already Exists '}
            else:
                user = User(username= username, first_name = first_name, last_name = last_name , email = email)
                user.set_password(password)
                user.save()
                profilePic = profilePicture(username = username,propicture= 'userProfile/avatar.png')
                profilePic.save()
                return redirect('login')
        else:
            regFailed = {'regF' : 'Registration Failed, try again! password and confirm password are not matched' }
        
        return render(request,'authentication/signup.html',regFailed)
    return render(request,'authentication/signup.html')

def authlogin(request):
    data={}
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username = email , password = password)
        
        if user is not None:
            login(request, user)
            return redirect('userprofile')
        else:
            data = {'a' : 'Login Failed'}
            return render(request,'authentication/login.html',data)
    return render(request,'authentication/login.html')

def resetPassword(request):
    return render(request,'authentication/resetPassword.html')


def userlogout(request):
    logout(request)
    # data = {'a' : 'Logout Successfull'}
    # return render(request,'authentication/login.html')
    return redirect('login')
