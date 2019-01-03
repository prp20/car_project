import base64
import os
import random
import pycrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
#from pycrypt import mainfn

def key_generation():
    password_provided = input("Enter your password ")
    print("\n Generating Key \n")
    password = password_provided.encode()

    salt = b'y\xcf\xa0\x98\xeb\xb3\xab\xd9wIkZ\x9d\xdc\xd3\xe4'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    print("Key successfully created. \n")
    print("Your Key is " + str(key) +"\n")
    print("***************************************************************************************\n")
    return key

def read_from_file(key):
    file = open("/home/prasad/python_crypt/python_crypt/pycrypted.txt","rb")
    encrypted_data = file.read()
    file.close()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)
    print("***************************************************************************************\n")
    print("decrypted Data\n")
    print("***************************************************************************************\n")
    return decrypted

def decode_data(data):
    decoded_data = data.decode()
    return decoded_data

def get_user_input():
    pin = input("Please enter your 4 digit pin : ")
    print("Your entered pin is : " + pin + "\n")
    return pin

def validate_pin(pin,data):
    n=59
    value = [data[i:i+n] for i in range(0, len(data), n)]
    for x in value:
        pin1 = x[52:56]
        if(pin == pin1):
            c = 1
        else:
            c = 0
            break
    if(c == 1):
        print("please turn on the car")
       # mainfn()
    else:
        print("invalid driver")
       # mainfn()

def user_logged_in():
    key = key_generation()
    decrypted_data = read_from_file(key)
    decoded_data = decode_data(decrypted_data)
    pin = get_user_input()
    validate_pin(pin, decoded_data)
   

    

