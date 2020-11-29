from django.shortcuts import render
from django.contrib import messages
from login.models import UserRegistrationModel
from user.models import UserFileUploadModel
from django.db.models import Avg
from itertools import groupby

# Create your views here.
def homeafterlogin(request):
    return render(request,'admin/adminhome.html')

def adminhome(request):
    if request.method == "POST":
        usid = request.POST.get('username')
        pswd = request.POST.get('password')
        print("User ID is = ", usid)
        if usid == 'admin' and pswd == 'admin':
            request.session['isloggedin'] = True
            request.session['role'] = 'user'
            #request.session['role'] = 'admin'
            users = UserRegistrationModel.objects.all()
            return render(request, 'admin/usermanage.html',{'users':users})
        else:
            print("Invalid Form")
            messages.success(request, 'Invalid Login Details')
    else:
        print("Not posted")
    return render(request,'admin_login.html',{})

def usermanage(request):
    users = UserRegistrationModel.objects.all()
    return render(request,'admin/usermanage.html',{'users':users})

def user_activation(request):
    if request.method == 'GET':
        uid = request.GET.get('uid')
        status = request.GET.get('status')
        if status == 'waiting':
            status = 'activated'
        else:
            status = 'waiting'
        print("PID = ", uid, status)
        UserRegistrationModel.objects.filter(id=uid).update(status=status)
        user = UserRegistrationModel.objects.all()
        return render(request,'admin/usermanage.html',{'users':user})
    else:
        print("No get request")
        pass


def uploadlog(request):
    logs = UserFileUploadModel.objects.all()
    return render(request, 'admin/uploadlog.html', {'logs': logs})

def Process_data(data):
    series = [
        {
            "algorithm": k,
            "data": [{"x":float(d["filesize"])/1048576.0,"y":d["dcount"]} for d in g],
        }
        for k, g in groupby(sorted(data, key=lambda d: [d["algorithms"],d['dcount']], reverse= True), key=lambda d: d["algorithms"])
    ]
    # print(series)
    return series

def charts(request):
    dataset = UserFileUploadModel.objects.values('algorithms', 'filesize').annotate(dcount=Avg('enc_time'))
    # print(dataset['filesize'])
    result = Process_data(dataset)
    # print(result)
    return render(request,'admin/charts.html',{'dataset':  result})