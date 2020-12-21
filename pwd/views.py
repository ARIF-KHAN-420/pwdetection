from django.shortcuts import render
# from django.http import HttpResponse
# Create your views here.




def resetPassword(request):
    return render(request,'resetPassword.html')
