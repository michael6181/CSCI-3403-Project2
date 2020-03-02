"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
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


host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# Generate a cryptographically random AES key
def generate_key():
    #length of key is "bit length"; 128bit is 16 bytes, 192bit is 24 bytes, 256bit is 32 bytes
    #data always encrypted/decrypted in 128bit (16 byte) blocks
    #128bit is secure for secret information, 192 or 256 needed for top secret
    #these higher key lengths are slower
    aes_key = os.urandom(16) #this creates 128 bit aes key
    return aes_key

# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    public_key = import_key(open("keys.pub","r").read())
    rsa_cipher = PKCS1_OAEP.new(public_key)
    enc_session_key = rsa_cipher.encrypt(session_key)
    return enc_session_key

# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    message = pad_message(message)
    iv = os.urandom(16) #16 byte initialization vector
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv) #creates cipher with our session key and iv
    enc_msg = cipher_aes.encrypt(str.encode(message)) #turns message into bytes and encrypts with session key and iv
    
    b64_iv = b64encode(iv).decode("utf-8") #necessary for json 
    b64_enc_msg = b64encode(enc_msg).decode("utf-8") #necessary for json
    
    json_data_str = json.dumps({'iv':b64_iv, 'ct':b64_enc_msg}) #create json message with iv and ciphertext (iv can be sent in plaintext) and convert to string to allow sending through socket
    return json_data_str.encode() #turned to bytes for transmission

# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    receiving = json.loads(message)
    rec_b64_iv = receiving.get("iv")
    rec_iv = b64decode(rec_b64_iv)
    rec_b64_ct = receiving.get("ct")
    rec_ct = b64decode(rec_b64_ct)
  
    decoding_AES = AES.new(session_key, AES.MODE_CBC, rec_iv)
    og_msg = decoding_AES.decrypt(rec_ct)
    return og_msg.decode()


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)
        else:
            print("okay")

        #Encrypt message and send to server
        enc_msg = encrypt_message(message, key)
        send_message(sock, enc_msg)

        #Receive and decrypt response from server
        rec_msg = receive_message(sock)
        rec_msg = rec_msg.decode()

        decrypted_msg = decrypt_message(rec_msg, key)
        print(decrypted_msg)
        
        if (decrypted_msg[:5] == "Valid"):
            file_to_access = input("Name of file to read/write: ")
            read_or_write = input("Would you like to 'r' read or 'w' write? ")
            file_and_action = file_to_access + " " + read_or_write
            
            #Encrypt message and send to server (file to access and whether to (r)ead or (w)rite)
            enc_msg = encrypt_message(file_and_action, key)
            send_message(sock, enc_msg)

            #Receive and decrypt response from server (if I can or can't read or write)
            rec_msg = receive_message(sock)
            rec_msg = rec_msg.decode()

            decrypted_msg = decrypt_message(rec_msg, key)
            print(decrypted_msg)

    finally:
        print('closing socket')
        sock.close()

if __name__ in "__main__":
    main()
