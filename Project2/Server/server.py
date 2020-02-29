"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:

    Michael Rogers
    Hans Hofmann
    John Palmer

"""

import socket
import os
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import import_key
from Crypto.Hash import SHA256

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    private_key = import_key(open("keys","r").read())
    rsa_decipher = PKCS1_OAEP.new(private_key)
    sesh_key = rsa_decipher.decrypt(session_key)
    return (sesh_key)

# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    receiving = json.loads(client_message)
    rec_b64_iv = receiving.get("iv")
    rec_iv = b64decode(rec_b64_iv)
    rec_b64_ct = receiving.get("ct")
    rec_ct = b64decode(rec_b64_ct)
    decoding_AES = AES.new(session_key, AES.MODE_CBC, rec_iv)
    og_msg = decoding_AES.decrypt(rec_ct)
    return og_msg.decode()

# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    message = pad_message(message)
    iv = os.urandom(16) #16 byte initialization vector
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv) #creates cipher with our session key and iv
    enc_msg = cipher_aes.encrypt(str.encode(message)) #turns message into bytes and encrypts with session key and iv
    
    b64_iv = b64encode(iv).decode("utf-8") #necessary for json 
    b64_enc_msg = b64encode(enc_msg).decode("utf-8") #necessary for json
    
    json_data_str = json.dumps({'iv':b64_iv, 'ct':b64_enc_msg}) #create json message with iv and ciphertext (iv can be sent in plaintext) and convert to string to allow sending through socket
    return json_data_str


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                #Generate the hashed password
                salted_pwd = password + line[1]
                byte_salt_pwd = str.encode(salted_pwd)
                hashed_password = SHA256.new(data=byte_salt_pwd).hexdigest()

                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)
                ciphertext_message = ciphertext_message.decode()

                #Decrypt message from client
                decrypted_msg = decrypt_message(ciphertext_message, plaintext_key)

                #Split response from user into the username and password
                decrypted_msg = decrypted_msg.rstrip()
                vals = decrypted_msg.split(" ")
                user = vals[0]
                pwd = vals[1]
                print(user, pwd)

                valid = verify_hash(user, pwd)
                if (valid == False):
                    response = "Invalid username and/or password."
                else:
                    response = "Valid user: Hello " + user 

                #Encrypt response to client
                ciphertext_response = encrypt_message(response, plaintext_key)


                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
