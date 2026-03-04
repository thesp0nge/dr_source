from django.http import HttpResponse
from django.shortcuts import render
from django.db import connection
from .models import User

# 1. Django FBV (Heuristic: parameter named 'request')
def search_view(request):
    # TAINT SOURCE: request object is tainted by framework
    # TAINT PROPAGATION: request.GET should become tainted
    query = request.GET.get('q')
    
    # VULNERABLE: SQL Injection via raw SQL
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE name = %s" % query)
    
    return HttpResponse("Result for %s" % query)

# 2. Django View with XSS
def profile_view(request):
    user_id = request.GET['id']
    # VULNERABLE: Direct rendering of user input in HttpResponse
    return HttpResponse("<h1>Profile of " + user_id + "</h1>")

# 3. Safe View (Constant Propagation)
def safe_view(request):
    # SAFE: Literal string
    return HttpResponse("Welcome to our site")
