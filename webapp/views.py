from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from . import models

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import os
# Create your views here.


def index(request):
    return render(request, 'login-5.html')


# def data_storage(request):
#     key = b'\x12\xf3yS\x907\xb43\xd6j\xb7\\lq\x83\xc2T\xc1\x80\x1fY\x8d\xfbq\xd3\xda\x80H\xda\xdeAF'
#     iv = b'\x16\xc1\xd4\x1d\xe8\x0c#\x86\xcf\x18@n\x88\x18\x06\xd3'

#     if request.method == 'POST':
#         label = request.POST.get('label')
#         textarea = request.POST.get('textarea').encode('utf-8')

#         # Message to be encrypted

#         # Encrypt the message
#         iv, ciphertext = encrypt_message(key, textarea)
#         print("Encrypted message:", ciphertext)

#         new_document = models.Document(label=label, textarea=ciphertext)
#         new_document.save()

#     all_documents = models.Document.objects.all()

#     all_decrypted_data = []

#     for data in all_documents:
#         d = {}
#         d['label'] = data.label
#         print("data", data.textarea)
#         d['textarea'] = decrypt_message(key, iv, data.get(['textarea'])

#     return render(request, 'data-storage.html', {"documents": all_documents})


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



# def encrypt_message(key, message):
#     # Generate a random initialization vector (IV)
#     iv = b'\x16\xc1\xd4\x1d\xe8\x0c#\x86\xcf\x18@n\x88\x18\x06\xd3'
    
#     # Pad the message to be a multiple of 128 bits (AES block size)
#     padder = padding.PKCS7(128).padder()
#     padded_message = padder.update(message) + padder.finalize()
    
#     # Create an AES cipher object
#     cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
#     # Encrypt the message
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
#     return iv, ciphertext

# def decrypt_message(key, iv, ciphertext):
#     # Create an AES cipher object
#     cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
#     # Decrypt the message
#     decryptor = cipher.decryptor()
#     padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    
#     # Unpad the message
#     unpadder = padding.PKCS7(128).unpadder()
#     message = unpadder.update(padded_message) + unpadder.finalize()
    
#     return message
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import base64

# def encrypt_message(key, iv, plaintext):
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     padded_plaintext = pad(plaintext, AES.block_size)
#     ciphertext = cipher.encrypt(padded_plaintext)
#     return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')

# def decrypt_message(key, iv, ciphertext):
#     cipher = AES.new(key, AES.MODE_CBC, base64.b64decode(iv))
#     decrypted_bytes = cipher.decrypt(base64.b64decode(ciphertext))
#     return unpad(decrypted_bytes, AES.block_size).decode('utf-8')

# def data_storage(request):
#     key = b'\x12\xf3yS\x907\xb43\xd6j\xb7\\lq\x83\xc2T\xc1\x80\x1fY\x8d\xfbq\xd3\xda\x80H\xda\xdeAF'
#     iv = b'\x16\xc1\xd4\x1d\xe8\x0c#\x86\xcf\x18@n\x88\x18\x06\xd3'

#     if request.method == 'POST':
#         label = request.POST.get('label')
#         textarea = request.POST.get('textarea').encode('utf-8')

#         # Encrypt the message
#         iv, ciphertext = encrypt_message(key, iv, textarea)

#         new_document = models.Document(label=label, textarea=ciphertext)
#         new_document.save()

#     all_documents = models.Document.objects.all()

#     all_decrypted_data = []

#     for data in all_documents:
#         d = {}
#         d['label'] = data.label
#         d['textarea'] = decrypt_message(key, iv, data.textarea)
#         d['encrypterd'] =  data.textarea
#         all_decrypted_data.append(d)

#     return render(request, 'data-storage.html', {"documents": all_decrypted_data})



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
