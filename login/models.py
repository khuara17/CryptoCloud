from django.db import models

# Create your models here.

class UserRegistrationModel(models.Model):

    name = models.CharField(max_length=100)
    email = models.EmailField()
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    contact = models.CharField(max_length=100)
    address = models.CharField(max_length=100)
    date_created = models.DateField(auto_now_add= True,blank=True, null=True)
    status = models.CharField(max_length=100, default='waiting')

    class Meta:
        db_table = 'users'

