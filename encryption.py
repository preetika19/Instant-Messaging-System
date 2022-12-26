#pip install hashlib
#pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import hashlib
import os

# The hash is computed from the initialization vector (IV) and the key
# Gives the hash value as a bytes literal
K12 = b'z$B&E)H@McQfTjWnZr4u7x!A%D*F-JaN'
IV = os.urandom(16) 
hash = K12+IV
hashed_data = bytes(hashlib.sha256(hash).hexdigest().encode())
print("Hash(Shared_key || IV) = " , hashed_data)

def byte_xor(s1, s2):
    return bytes([_a ^ _b for _a, _b in zip(s1, s2)])

# Encrypt the plaintext and return the cipher text
# AES is used to perform encryption
# Gives the cipher text
def encrypt(msg, K12):
    cipher = AES.new(K12, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    print("Encrypted Ciphertext with AES(shared key):" , ciphertext)
    return ciphertext, nonce, tag

# Decrypt the cipher text and return the plain text
def decrypt(ciphertext, K12, nonce, tag):
    cipher = AES.new(K12, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print("Decrypted Plaintext with AES shared key:" , plaintext)
    return plaintext

sendmsg = b"Hello"
print("Plaintext:", sendmsg)
msg = byte_xor(sendmsg,hashed_data)
print("Ciphertext (Plaintext XOR Hash(Shared_key || IV)):", msg)
ciphertext, nonce, tag = encrypt(msg, K12)
decrypted_val = decrypt(ciphertext, K12, nonce, tag)
try:
    final = byte_xor(decrypted_val,hashed_data)
    print("Decrypted Ciphertext is: ", final)
    if (final == sendmsg):
        print("The message is authentic.")
    else:
        print("Message corrupted")
except ValueError:
    print("Key incorrect or message corrupted")