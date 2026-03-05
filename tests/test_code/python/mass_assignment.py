from django import forms
from .models import User

# VULNERABLE: Django Mass Assignment via Form
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = '__all__' # Line 7

# VULNERABLE: Direct Mass Assignment in View
def update_user(request, user_id):
    user = User.objects.get(id=user_id)
    # Taint flows from request.POST to save()
    user.save(request.POST) # Line 13
