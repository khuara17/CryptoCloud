from django import forms
from .models import UserRegistrationModel

class UserRegisterForm(forms.ModelForm):

    name = forms.CharField(max_length=20)
    email = forms.EmailField()
    username = forms.CharField(max_length=30)
    password = forms.CharField(max_length=30)
    contact = forms.CharField(max_length=10)
    address = forms.CharField(max_length=100)
    date_created = forms.DateField(required=False)
    status = forms.CharField(widget=forms.HiddenInput(), initial='waiting', max_length=100)

    class Meta():
        model = UserRegistrationModel
        fields = '__all__'