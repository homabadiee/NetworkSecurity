from django.shortcuts import render
import hashlib
import os

pepper = 'scrt'

def index(request):
    return render(request, 'index.html')

def submit_data(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        hashed_passwords('users.txt', username, password)
        salt_pepper_hashed_passwords('s_users.txt', username, password)
    return render(request, 'welcome.html')


def salt_pepper_hashed_passwords(filename, username, password):
    with open(filename, 'a') as file:
        salt = os.urandom(16)
        hash_value = hashlib.md5(salt + password.encode() + pepper.encode()).hexdigest()
        file.write(f"{username},{password},{hash_value}, {salt}\n")


def hashed_passwords(filename, username, password):
    with open(filename, 'a') as file:
        hash_value = hashlib.md5(password.encode()).hexdigest()
        file.write(f"{username},{password},{hash_value}\n")

