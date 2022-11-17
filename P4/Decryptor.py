from asyncore import read
import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def read_data(filename):
    with open(filename, 'rb') as file:
        data = file.read()
    return data

def store_data(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)

def decrypt_file(filename, output, key, iv):

    data = read_data(filename)
    decrypted_data = decrypt_data(data, key, iv, algo='ChaCha20')
    store_data(decrypted_data, output)

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

def decrypt_data(data, key, iv, algo):
    cipher = None
    if algo=='AES':
        cipher_algo = algorithms.AES(key)
        cipher = Cipher(cipher_algo, modes.CBC(iv))
        size = 128
    if algo=='ChaCha20':
        nonce = base64.b64decode(read_data('nonce.txt'))
        cipher_algo = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(cipher_algo, mode = None)
        size = 256

    decryptor = cipher.decryptor()
    validation_data = decryptor.update(data) + decryptor.finalize()
    unpadded_data = unpadder(validation_data, size)
    print(unpadded_data)

    return unpadded_data

def main(args):
    if len(args) < 3:
        print('Invalid argument')
        exit()

    filename = args[1]
    output = args[2]

    key = base64.b64decode(read_data('key.txt'))  
    iv =  base64.b64decode(read_data('iv.txt'))
    decrypt_file(filename, output, key, iv)

    return 0

if __name__ == "__main__":
    main(sys.argv)
