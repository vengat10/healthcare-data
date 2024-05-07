from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from . import models

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import os

from django.contrib.auth.models import User, auth
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

# Create your views here.


def index(request):
    return render(request, 'login-5.html')

def login_view(request):
    if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(username=username, password=password)
            print("user ", user)
            if user is not None:
                login(request, user)
                # Redirect to a success page.
                return redirect('/data-storage')
            else:
                print("Invalid Login")
                # Return an 'invalid login' error message.
                return render(request, 'login.html', {'error_message': 'Invalid login'})
    return render(request, 'login.html', {'error_message': ''})



def register_view(request):
    if request.method == "POST":
        username = request.POST["name"]
        email = request.POST["email"]
        password = request.POST["password"]      
        user = User.objects.create_user(email, email, password)
        user.first_name = username
        user.is_active = False
        user.save()
        return redirect('/')
    return render(request, 'register.html', {'error_message': ''})


def logout_view(request):
    logout(request)
    return redirect('/')

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')

def decrypt_message(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_bytes, AES.block_size).decode('utf-8')

def data_storage(request):
    key = b'\x12\xf3yS\x907\xb43\xd6j\xb7\\lq\x83\xc2T\xc1\x80\x1fY\x8d\xfbq\xd3\xda\x80H\xda\xdeAF'
    iv = b'\x16\xc1\xd4\x1d\xe8\x0c#\x86\xcf\x18@n\x88\x18\x06\xd3'

    if request.method == 'POST':
        label = request.POST.get('label')
        textarea = request.POST.get('textarea').encode('utf-8')

        # Encrypt the message
        iv_b64, ciphertext_b64 = encrypt_message(key, iv, textarea)

        new_document = models.Document(label=label, textarea=ciphertext_b64)
        new_document.save()

    all_documents = models.Document.objects.all()

    all_decrypted_data = []

    for data in all_documents:
        d = {}
        d['label'] = data.label
        d['encrypterd'] =  data.textarea
        d['textarea'] = decrypt_message(key, iv, data.textarea)
        all_decrypted_data.append(d)

    return render(request, 'data-storage.html', {"documents": all_decrypted_data})

def view_data(request):
    all_decrypted_data = {}
    if request.method == 'GET':
        en = request.GET["en"]
        dy = request.GET["dy"]
        all_decrypted_data ={
            'en': en,
            'dy': dy
        }
    print("all_decrypted_data", all_decrypted_data)
    return render(request, 'view-data.html', all_decrypted_data)
