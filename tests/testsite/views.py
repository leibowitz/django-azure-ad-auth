from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def login_successful(request):
    return render(request, 'login-successful.html')