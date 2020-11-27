from django.shortcuts import render

# Create your views here.
from django.shortcuts import render,HttpResponseRedirect
from .models import UserRegistrationModel
from .forms import UserRegisterForm
from django.contrib import messages
from rest_framework.decorators import api_view
from django.urls import reverse

# Create your views here.

def userregister(request):
    if request.method == 'POST':
        myform = UserRegisterForm(request.POST)
        if myform.is_valid():
            try:
                rslt = myform.save()
                print(rslt)
            except:
                print("Username Exist")
            return HttpResponseRedirect(reverse('userlogin'))
        else:
            print(myform.errors)
    else:
        myform = UserRegisterForm()
    return render(request, 'user_registration.html', {'form': myform})
    #return render(request, 'user_registration.html', {})

def user_login(request):
    #return render(request, 'user/userregister.html', {'form': form})

    return render(request,'user_login.html')

def admin_login(request):
    return render(request, 'admin_login.html', {})

def userlogin_check(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(username, password)
        try:
            check = UserRegistrationModel.objects.get(username=username)
            if check.password == password:
                #request.session['id'] = check.id
                status = check.status
                if status == "activated":
                    request.session['isloggedin'] = True
                    request.session['loggeduser'] = check.username
                    request.session['email'] = check.email
                    request.session['role'] = 'user'
                    print(check.username,"Has Logged In")
                    return render(request, 'user/userhome.html', {})
                else:
                    # messages.error(request, 'Your Account Not yet activated')
                    messages.success(request, 'Your Account is Not yet activated, Wait till admin Activates your account')
                    print("Your Account Not yet activated")
                    return render(request, 'user_login.html')
            else:
                messages.success(request, 'Invalid Username Or Password, Please try Again')
                print("Invalid Username Or Password")
                return render(request, 'user_login.html')
            # return render(request, 'user_login.html', {})
        except:
            messages.success(request, 'Some Error Occured, Please try again later.')
            pass
    return render(request, 'user_login.html')


