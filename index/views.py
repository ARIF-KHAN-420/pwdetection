from django.shortcuts import render

# Create your views here.
def index(request):
    data = {'d' : "Copy a Url or Link and paste it."}
    return render(request,'index.html',data)