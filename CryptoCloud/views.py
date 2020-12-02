from django.shortcuts import render,HttpResponseRedirect
from django.urls import reverse
def index(request):
    return render(request,'index.html',{})

def generic(request):
    return render(request,'generic.html',{})

def logout(request):
    try:
        del request.session['isloggedin']
        del request.session['loggeduser']
        del request.session['email']
        del request.session['role']
    except KeyError:
        pass
    return HttpResponseRedirect(reverse('index'))
    #return render(request,'index.html',{})