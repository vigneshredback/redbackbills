from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

class RegisterForm(forms.ModelForm):
    # full_name = forms.CharField(max_length=100, required=True, help_text="Enter your full name.")
    # password = forms.CharField(widget=forms.PasswordInput, required=True)
    # confirm_password = forms.CharField(widget=forms.PasswordInput, required=True)

    class Meta:
        model = User
        fields = '__all__'

    # def clean(self):
    #     cleaned_data = super().clean()
    #     password = cleaned_data.get('password')
    #     confirm_password = cleaned_data.get('confirm_password')

    #     if password != confirm_password:
    #         raise forms.ValidationError("Passwords do not match.")
    #     return cleaned_data

    # def save(self, commit=True):
    #     user = super().save(commit=False)
    #     full_name = self.cleaned_data['full_name']
    #     user.first_name, user.last_name = full_name.split(' ', 1)  # Split full name
    #     user.set_password(self.cleaned_data['password'])  # Hash the password
    #     if commit:
    #         user.save()
    #     return user

class VerificationForm(forms.Form):
    code = forms.CharField(max_length=6)
