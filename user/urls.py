from django.urls import path

from . import views
urlpatterns = [
    path('home/',views.home,name='home'),
    path('myfile/',views.myfile,name='myfile'),
    path('userbuckets/',views.UserBucket,name="userbuckets"),
    path('createbucket/',views.CreateBucket,name="createbucket"),
    path('bucketlist/',views.BucketList,name="bucketlist"),
    path('upload/<id>/',views.UploadFiles,name='upload'),
    path('UploadToCloud/',views.UploadToCloud,name="UploadToCloud"),
    path('download/<id>/',views.DownloadFile,name="download"),
    path('decrypt/',views.DecryptFile,name="decrypt"),
    path('delete/<id>',views.DeleteFile,name="delete"),
    path('deletebucket/<id>',views.DeleteBucket,name="deletebucket"),
    path('charts/',views.charts,name='usercharts'),
]