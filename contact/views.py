from django.shortcuts import render
from .models import contact
# Create your views here.
def contactFunction(request):
    if request.method == 'POST':
        usernme = request.POST['usernme']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        message = request.POST['message']
        
        info = contact(username= usernme, first_name= first_name, last_name= last_name, email= email, message= message)
        
        info.save()
        data = {'data' : 'Message Sent'}
        return render(request,'contact.html', data)
    return render(request,'contact.html')