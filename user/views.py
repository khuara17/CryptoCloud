import os
import time
import secrets
import uuid
from itertools import groupby

from django.db.models import Avg
from django.http import HttpResponse, Http404, FileResponse, HttpResponseRedirect
from django.conf import settings
from django.contrib import messages
from django.shortcuts import render
from .algorithms import AESCipher,BlowfishCipher,HybridAESRSACipher

from pathlib import Path

# Create your views here.
from user.models import UserBucketCreatModel, UserFileUploadModel, DecryptRequestModel
from .forms import UserFileUploadForm, DecryptRequestForm

# User Home Page
def home(request):
    if 'isloggedin' in request.session:
        return render(request, 'user/userhome.html', {})
    else:
        return render(request, 'user_login.html', {})

# View Uploaded Files
def myfile(request):
    if 'isloggedin' in request.session:
        useremail = request.session['email']
        obj = UserFileUploadModel.objects.filter(email=useremail)
        return render(request,'user/myfiles.html',{'objects':obj})
    else:
        return render(request, 'user_login.html', {})


################# Bucket Section ###################
# User Bucket Temp
def UserBucket(request):
    if 'isloggedin' in request.session:
        return render(request,'user/create_bucket.html',{})
    else:
        return render(request, 'user_login.html', {})


# Create user Bucket Back
def CreateBucket(request):
    if 'isloggedin' in request.session:
        if request.method == 'POST':
            username = request.POST.get('username')
            email = request.POST.get('email')
            bucketname = request.POST.get('bucket_name')
            bucket = UserBucketCreatModel.objects.filter(username=username)

            access_key = secrets.token_urlsafe(8) #creating 8 digits random access key
            if not bucket.filter(username=username,email=email, bucketname=bucketname).exists():
                try:
                    UserBucketCreatModel.objects.create(username=username, email=email, bucketname=bucketname,accesskey=access_key)
                    messages.success(request, 'Your Bucket has been created successfully')
                    print(username, email, bucketname)
                    print("Bucket Created")
                    dict = UserBucketCreatModel.objects.filter(email=email)
                    return render(request, 'user/bucket_list.html', {'buckets': dict})
                    # return render(request, 'user/bucket_list.html', {'buckets': 'Your Bucket has been created successfully'})
                except:
                    messages.success(request, 'Bucket Name Already exist')
                    print("Bucket Not created, something wrong")
                    pass
            else:
                print("Bucket Already Exists")
                error = "Bucket Already Exists"
                messages.success(request, 'Bucket With This Name Already Exists')
                return render(request, 'user/create_bucket.html', {'error':error})
        else:
            usremail = request.session['email']
            dict = UserBucketCreatModel.objects.filter(email=usremail)
            return render(request, 'user/bucket_list.html', {'buckets': dict})
        # return render(request,'user/create_bucket.html',{})
    else:
        return render(request, 'user_login.html', {})

# List of Bucket User Own
def BucketList(request):
    if 'isloggedin' in request.session:
        usremail = request.session['email']
        dict = UserBucketCreatModel.objects.filter(email=usremail)
        return render(request,'user/bucket_list.html',{'buckets':dict})
    else:
        return render(request, 'user_login.html', {})

# Delete Bucket
def DeleteBucket(request,id):
    if 'isloggedin' in request.session:
        print("Deleted-",id)
        UserBucketCreatModel.objects.filter(id=int(id)).delete()
        print("user with id :-",id,"has been deleted")
        return render(request,'user/bucket_list.html',{})
    else:
        return render(request, 'user_login.html', {})

############# Upload And Encryption Section ######################

# Upload File Temp
def UploadFiles(request,id):
    if 'isloggedin' in request.session:
        check = UserBucketCreatModel.objects.filter(id=id)
        return render(request, 'user/upload.html', {'objects': check})
    else:
        return render(request, 'user_login.html', {})

# Upload File Back
def UploadToCloud(request):
    if request.method == "POST":
        print('POST Method Works Fine')
        usremail = request.session['email']
        form = UserFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            print("form is valid")
            # id = form.cleaned_data['id']
            algo = form.cleaned_data['algorithms']
            form.save()
            enc_time,file_size,public_key = Encrypt_file(form,algo)
            print("encryption Done")
            t = UserFileUploadModel.objects.last()
            t.filesize = file_size
            t.enc_time = round(enc_time,3)
            t.publickey = public_key
            t.save()
            print(round(enc_time,3),file_size)
            # file_temp = tempfile.NamedTemporaryFile()
            # file_temp.write(ipfile.read())
            # print(os.stat(ipfile).st_size)
            messages.success(request, 'Your File has been Uploaded successfully')
            dict = UserFileUploadModel.objects.filter(email=usremail)
            return render(request, 'user/myfiles.html', {'objects': dict})
        else:
            print(form.errors)
            return render(request,'user/bucket_list.html',{'upload_error' : 'Error occurred while uploading the file'})
    else:
        return render(request,'user/bucket_list.html',{})
#
# def UserFileUpload(request):
#     if 'idloggedin' in request.session:
#         return render(request,'userfileupload.html',{})
#     else:
#         return render(request, 'user_login.html', {})

# Encrypt While Uploading
def Encrypt_file(form,selectedalgo):
    t1_start = time.process_time()
    userfile = UserFileUploadModel.objects.last()
    # path = 'UserUploads/{0}/{1}/{2}'.format(form.cleaned_data['name'],form.cleaned_data['bucketname'],form.cleaned_data['userfile'])
    # ext = userfile.split('.')[-1]
    path = str(userfile.userfile)
    # public = str(userfile.publickey)
    filename = path.split("/")[-1]
    public = "%s.%s" % (path[:-len(filename)],'public.pem')
    private = "%s-%s.%s.%s" % (path[:-len(filename)],"private",filename,"pem")
    print(public,"--",private)
    file = os.path.join(settings.MEDIA_ROOT, path)
    public_key = os.path.join(settings.MEDIA_ROOT, public)
    private_key = os.path.join(settings.MEDIA_ROOT, private)
    accesskey = userfile.accesskey
    secretkey = form.cleaned_data['secretkey']
    file_size = os.stat(file).st_size
    # file_size = os.path.getsize(file)
    # file_size = size(statinfo)   # TO convert into kb or mb representation
    # print(file_size)
    # file = open(path, 'w')
    if selectedalgo == 'BLOWFISH':
        algo = BlowfishCipher(secretkey, accesskey)
        algo.encrypt_file(file)
        public_key = "Null"
    elif selectedalgo == 'AES-256':
        algo = AESCipher(secretkey, accesskey)
        algo.encrypt_file(file)
        public_key = "Null"
    elif selectedalgo == 'RSA & AES':
        algo = HybridAESRSACipher(private_key, public_key)
        algo.generate_keys()
        algo.encrypt_file(file)
    t1_stop = time.process_time()
    os.remove(file)
    return t1_stop-t1_start, file_size, public_key


############### Encryption part Ends Here ######################

############### Download file   ##################
def DownloadFile(request, id):
    if 'isloggedin' in request.session:
        data = UserFileUploadModel.objects.filter(id=id)
        return render(request,'user/download.html',{'objects':data})
    else:
        return render(request, 'user_login.html', {})

# def handle_uploaded_file(f):
#     private = os.path.abspath(f.name)
#     destination = open(private, 'wb+')
#     for chunk in f.chunks():
#         destination.write(chunk)
#     destination.close()
#     return private

# Initiating Decryption while downloading
def DecryptFile(request):
    if 'isloggedin' in request.session:
        # form = DecryptRequestForm()
        if request.method == 'POST':
            id = request.POST.get('id')
            # instance = DecryptRequestModel.objects.get(id=id)
            form = DecryptRequestForm(request.POST,request.FILES)

            if form.is_valid():
                # if a GET (or any other method) we'll create a blank form
                algorithm = form.cleaned_data['algorithms']
                print(algorithm)
                form.save()
                if algorithm == 'BLOWFISH' or algorithm == 'AES-256':
                    key = request.POST.get('key')
                    print(key)
                    res = Decryption(id, key, "sym")
                else:
                    # private_key = request.FILES['private_key']
                    private_key = form.cleaned_data['private_key']
                    private = os.path.abspath(private_key.name)
                    print(private_key)
                    print(os.path.abspath(private_key.name))
                    res = Decryption(id, private, "asym")

                if res == "Key_Mismatch" or res == "Key Not Found":
                    print("Wrong Key")
                    return render(request,'user/myfiles.html',{'res':'Wrong Key'})
                elif res == "Data_Not_Found":
                    print("Data Not Found")
                    return render(request,'user/download.html',{'res':'Data Not Found'})
                else:
                    data = UserFileUploadModel.objects.get(id=id)
                    file_path2 = os.path.join(settings.MEDIA_ROOT, str(data.userfile))
                    if os.path.exists(file_path2):
                        with open(file_path2, 'rb') as fh:
                            response = HttpResponse(fh.read(), content_type="application/vnd.ms-excel")
                            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path2)
                            return response
                    os.remove(file_path2) # While decrypting, save temprorily decrypted file to server for downloading.
                    return render(request, 'user/charts.html', {'res': 'The file has decrypted'})
            else:
                print(form.errors)
                return render(request,'user/download.html',{'res':'The file not decrypted'})
    else:
        return render(request, 'user_login.html', {})

# Use Decryption algo to decrypt
def Decryption(id,key,algtype):
    data = UserFileUploadModel.objects.get(id=id)
    if algtype == 'sym':
        if data.secretkey == key:
            t1_start = time.process_time()
            print(data.userfile)
            file_path = os.path.join(settings.MEDIA_ROOT, str(data.userfile) + ".enc")
            if os.path.exists(file_path):
                accesskey = data.accesskey
                if data.algorithms == "AES-256":
                    algo = AESCipher(key, accesskey)
                    res = algo.decrypt_file(file_path)
                elif data.algorithms == "BLOWFISH":
                    algo = BlowfishCipher(key, accesskey)
                    res = algo.decrypt_file(file_path)
                if(res=="Decrypted"):
                    t1_stop = time.process_time()
                    dec_time = t1_stop - t1_start
                    print("decrypted Successfully")
                    print(dec_time)
                    data.dec_time = dec_time
                    data.save()
                    decrypt_result = "Decrypted Successfully"
                else:
                    decrypt_result = "Decryption Failed"
                return decrypt_result
            else:
                return "Data_Not_Found"
        else:
            return "Key_Mismatch"
    elif algtype == 'asym':
        # if os.path.exists(key):
        t1_start = time.process_time()
        file_path = os.path.join(settings.MEDIA_ROOT, str(data.userfile) + ".enc")
        if os.path.exists(file_path):
            if data.algorithms == "RSA & AES":
                algo = HybridAESRSACipher(key)
                res = algo.decrypt_file(file_path)
            print(res)
            t1_stop = time.process_time()
            dec_time = t1_stop - t1_start
            print(t1_stop - t1_start)
            data.dec_time = dec_time
            data.save()
            return dec_time
        else:
            print("File not found")
            return "Data_Not_Found"
    # else:
    #     print("Key Not Found")
    #     return "Key Not Found"


################ Decryption part ends here ###############

################ Delete Uploaded Files    #################

def DeleteFile(request,id):
    if 'isloggedin' in request.session:
        row = UserFileUploadModel.objects.get(id=id)
        file_path = os.path.join(settings.MEDIA_ROOT, str(row.userfile) + ".enc")
        if os.path.exists(file_path):
            os.remove(file_path)
        UserFileUploadModel.objects.filter(id=id).delete()
        return HttpResponseRedirect('/user/myfile/')
    else:
        return render(request, 'user_login.html', {})

################# Show Charts  #####################


def Process_data(data):
    # processed = groupby(sorted(data, key=lambda d: [d["algorithms"],d["filesize"]]), key=lambda d: d["algorithms"])
    # print(processed)
    # res = {}
    # for item in processed:
    #     res.setdefault(item['algorithms'], []).append(item['dcount'])
    series = [
        {
            "algorithm": k,
            "data": [{"x":float(d["filesize"])/1048576.0,"y":d["dcount"]} for d in g],
        }
        for k, g in groupby(sorted(data, key=lambda d: [d["algorithms"],d['dcount']], reverse= True), key=lambda d: d["algorithms"])
    ]
    print(series)
    return series



def charts(request):
    if 'isloggedin' in request.session:
        dataset = UserFileUploadModel.objects.values('algorithms', 'filesize').annotate(dcount=Avg('enc_time'))
        # print(dataset['filesize'])
        result = Process_data(dataset)
        return render(request,'user/charts.html',{'dataset':  result})
    else:
        return render(request, 'user_login.html', {})

