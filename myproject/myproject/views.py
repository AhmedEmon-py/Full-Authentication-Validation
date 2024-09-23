from django.shortcuts import render,redirect
from django.http import HttpResponse

from django.contrib.auth import authenticate,login,logout

from django.contrib.auth.decorators import login_required

from myapp.models import*

from django.contrib import messages

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError
from django.http import Http404


def loginPage(req):
    if req.method=='POST':
        
        username=req.POST.get("username")
        password=req.POST.get("password")
        
        if not username or not password:
            messages.warning(req,"Both username and password are required")
            return render(req,"loginPage.html")
        
        user=authenticate(username=username,password=password)
        
        if user is not None:
            login(req,user)
            messages.success(req,"Login Successfully")
            
            return redirect("homepage")  
        else:
            messages.warning(req,"Invalid username or password")


    return render(req,"loginPage.html")



def signupPage(req):
    if req.method=='POST':
        
        username=req.POST.get("username")
        email=req.POST.get("email")
        usertype=req.POST.get("usertype")
        password=req.POST.get("password")

        if not all([username, email, usertype, password]):
            messages.warning(req,"All fields are required")
            return render(req,"signupPage.html")
        
        try:
            validate_email(email)

        except ValidationError:
            messages.warning(req,"Invalid email format")
            return render(req,"signupPage.html")
        
        if password != password:
            messages.warning(req,"Password do not match")
            return render(req,"signupPage.html")
        
        if len(password)<8:
            messages.warning(req,"Password must be at least 8 characters long")
            return render(req,"signupPage.html")
        
        if not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
            messages.warning(req,"Password must contain both letters and numbers")
            return render(req,"signupPage.html")
        
        try:
            user=CustomUser.objects.create_user(
                username=username,
                email=email,
                usertype=usertype,
                password=password
            )
            messages.success(req,"Account created successfully!")
            return redirect("loginPage")
        except IntegrityError:
            messages.warning(req,"Username or email already exists")
            return render(req,"signupPage.html")
        
    return render(req,"signupPage.html")

        



def homepage(req):

    return render(req,"homepage.html")

def logoutPage(req):
    
    logout(req)
    messages.success(req,"You have been logged out successfully")
    
    return redirect("loginPage")


@login_required 

def homepage(req):
    
    return render(req,"homepage.html")

