import base64
import os
import random
from pycrypt2 import user_logged_in
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import time

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
    print("***************************************************************************************\n")
    return key

def write_to_file(data):
    file = open("/home/prasad/python_crypt/python_crypt/random_list.txt","wb")
    for x in data:
        file.write(x)
    time.sleep(5)
    file.close()

def read_from_file():
    f = open("/home/prasad/python_crypt/python_crypt/random_list.txt","rb")
    data = f.read()
    f.close()
    return data

def file_read_and_encrypt(key):
    data = read_from_file()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    print("***************************************************************************************\n")
    print("Encrypted Data\n")
    print("***************************************************************************************\n")
    file = open("/home/prasad/python_crypt/python_crypt/pycrypted.txt","wb")
    file.write(encrypted)
    file.close()

def encode_array(array_list):
    new_list = [x.encode() for x in array_list]
    return new_list

def generate_random_numbers():
    print("Generating random numbers\n")
    print("***************************************************************************************\n")
    a = []
    for j in range(50):
        val = random.randint(10**51, 10**52)
        a.append(val)
    return a

def sum_of_digits(randomNumber):
    n=randomNumber
    int_n = [int(x) for x in n]
    total = []
    for x in int_n:
        tot = 0
        val = x
        while(x>0):
            dig=x%10
            tot=tot+dig
            x=x//10
        finval = append_str(val, tot)
        total.append(finval)  
    return total

def get_user_input():
    pin = input("Please enter your pin details : ")
    print("your pin is : " + pin + "\n")
    #if(len(str(pin)) != 4)
    return pin

def append_str(first_value, second_value):
    str_first_value = str(first_value)
    str_second_value = str(second_value)
    string_final = str_first_value + str_second_value
    return string_final

def create_user():
    print("\n Creating New User \n")
    print("***************************************************************************************")
    key = key_generation()
    random_numbers = generate_random_numbers()
    pin = get_user_input()
    random_numbers_with_pin = []
    for x in random_numbers:
        val = append_str(x, pin)
        random_numbers_with_pin.append(val)
    array_of_total = sum_of_digits(random_numbers_with_pin)
    encoded_array = encode_array(array_of_total)
    write_to_file(encoded_array)
    file_read_and_encrypt(key)


def mainfn():
    print("***************************************************************************************\n")
    print("Welcome to Prasad Car entry Project")
    print("***************************************************************************************\n")
    print("If you are an existing user Press 1 \nIf New User Press 2")
    print("***************************************************************************************\n")
    userloginval = input("Please enter your choice : ")
    if( userloginval == '1' ):
        print("Welcome back exisitng user")
        print("***************************************************************************************\n")
        user_logged_in()
    elif( userloginval == '2' ):
        print("Welcome New User. Let's create your account.")
        print("***************************************************************************************\n")
        create_user()



