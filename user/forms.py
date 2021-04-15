import uuid

from django import forms
from .models import UserFileUploadModel,DecryptRequestModel


# def get_upload_path(instance):
#     return 'UserUploads/Tempfile/'

class DecryptRequestForm(forms.ModelForm):
    # id = forms.IntegerField()
    # file_name = forms.CharField(max_length=200)
    # algorithms = forms.CharField(max_length=200,required=False)
    key = forms.CharField(max_length=200,required=False)
    private_key = forms.FileField(required=False)

    class Meta():
        model = DecryptRequestModel
        fields = ['file_name','algorithms','key','private_key']


class UserFileUploadForm(forms.ModelForm):
    name = forms.CharField(max_length=200)

    def __init__(self, *args, **kwargs):
        super(UserFileUploadForm, self).__init__(*args, **kwargs)
        ALGORITHMS = [
            ('BLOWFISH', 'BLOWFISH'),
            ('AES-256', 'AES-256'),
            # ('RSA', 'RSA'),
            ('RSA & AES', 'RSA & AES'),
            ('RSA & BLOWFISH', 'RSA & BLOWFISH'),
        ]
        self.fields['algorithms'] = forms.ChoiceField(
            choices=ALGORITHMS)
    class Meta():
        model = UserFileUploadModel
        fields = ['id','name','email','bucketname','accesskey','secretkey' ,'filename', 'userfile', 'algorithms']