import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def read_data(filename):
    with open(filename, 'rb') as file:
        data = file.read()
    return data

def generate_crypto_materials():
    key = os.urandom(32)
    return key

def store_data(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)

def store_string(string, filename):
    with open(filename, 'w') as file:
        file.write(string)

def encrypt_file(filename, output, key):
    data = read_data(filename)
    encrypted_data = encrypt_data(data, key)
    store_data(encrypted_data, output)

    return None

def padder(data, size):
    padder = padding.PKCS7(size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

def unpadder(data, size):
    unpad = padding.PKCS7(size).unpadder()
    unpadded_data = unpad.update(data)
    unpadded_data += unpad.finalize()
    return unpadded_data

def encrypt_data(data, key):
    cipher = None
    cipher_algo = algorithms.AES(key)
    cipher = Cipher(cipher_algo, modes.ECB())
    size = 128

    encryptor = cipher.encryptor()
    padded_data = padder(data, size)
    ct = encryptor.update(padded_data) + encryptor.finalize()

    #decryptor = cipher.decryptor()
    #validation_data = decryptor.update(ct) + decryptor.finalize()
    #unpadded_data = unpadder(validation_data, size)
    #print(unpadded_data)

    return ct

def main(args):
    if len(args) < 3:
        print('Invalid argument')
        exit()

    filename = args[1]
    output = args[2]
    #algo = args[3] #FIXME this is for version 0.9

    key,iv = generate_crypto_materials()
    encrypt_file(filename, output, key)
    print('The used key is: ' + str(base64.b64encode(key)))
    print('The used iv is: ' + str(base64.b64encode(iv)))

    store_data(base64.b64encode(key), 'key.txt')

    return 0

if __name__ == "__main__":
    main(sys.argv)
