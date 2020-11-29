from django.db import models
import os
import uuid
# Create your models here.

class UserBucketCreatModel(models.Model):
    username = models.CharField(max_length=200)
    email = models.CharField(max_length=200)
    bucketname = models.CharField(max_length=200)
    accesskey = models.CharField(max_length=200)
    publickey = models.CharField(max_length=200, null=True)
    date_created = models.DateField(auto_now_add=True, blank=True, null=True)

    def __str__(self):
        return self.bucketname
    class Meta:
        db_table = "userbuckets"

#
# def get_upload_path(instance):
#     return 'UserUploads/Tempfile/'

class DecryptRequestModel(models.Model):

    file_name = models.CharField(max_length=200)
    algorithms = models.CharField(max_length=200)
    key = models.CharField(max_length=200)
    private_key = models.FileField(upload_to='UserUploads/Tempfile/')
    date_decrypted = models.DateField(auto_now_add=True, blank=True, null=True)
    # file_id = models.ForeignKey('UserFileUploadModel', on_delete=C)

    def __str__(self):
        return self.algorithms

    class Meta:
        db_table = "decryption"

# class UserFileModel(models.Model):
#     username = models.CharField(max_length=200)
#     email = models.CharField(max_length=200)
#     bucketname = models.CharField(max_length=200)
#     accesskey = models.CharField(max_length=200)
#     secretkey = models.CharField(max_length=200)
#     filename = models.CharField(max_length=200)
#     userfile = models.FileField(upload_to='media/')
#
#     def __str__(self):
#         return os.path.basename(self.userfile.name)
#     class Meta:
#         db_table = "userfiles"


def get_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = "%s.%s" % (uuid.uuid4(), ext)
    return 'UserUploads/{0}/{1}/{2}'.format(instance.name,instance.bucketname,filename)

class UserFileUploadModel(models.Model):

    name = models.CharField(max_length=200)
    email = models.CharField(max_length=200)
    bucketname = models.CharField(max_length=200)
    accesskey = models.CharField(max_length=200)
    secretkey = models.CharField(max_length=200)
    publickey = models.CharField(max_length=200, null=True)
    filename = models.CharField(max_length=200)
    userfile = models.FileField(upload_to=get_upload_path)
    ALGORITHMS = [
        ('BLOWFISH', 'BLOWFISH'),
        ('AES-256', 'AES-256'),
        ('RSA', 'RSA'),
        ('RSA & AES', 'RSA & AES'),
        ('AES & BLOWFISH', 'AES & BLOWFISH'),
    ]
    algorithms = models.CharField(max_length=15, choices=ALGORITHMS, default='BLOWFISH')
    filesize = models.CharField(max_length=80)
    enc_time = models.CharField(max_length=80)
    dec_time = models.CharField(max_length=80,null=True)
    date_uploaded = models.DateField(auto_now_add=True, blank=True, null=True)

    def __str__(self):
        return os.path.basename(self.userfile.name)

    class Meta:
        db_table = "userfiles"

    def delete(self, *args, **kwargs):
        self.userfile.delete()
        super().delete(*args, **kwargs)