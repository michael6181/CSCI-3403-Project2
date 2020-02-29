"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""
import random
import string
from Crypto.Hash import SHA256


user = input("Enter a username: ")
password = input("Enter a password: ")

# Create a salt and hash the password
salt = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for x in range(16)) #systemrandom uses dev/urandom
salted_pwd = password + salt
byte_salt_pwd = str.encode(salted_pwd)
hashed_password = SHA256.new(data=byte_salt_pwd).hexdigest()

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, salt, hashed_password))
    print("User successfully added!")
