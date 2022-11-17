import sys
from  cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# data_to_encrypt -> data that we are gonna encrypt
# public_key -> data that contains the public key
# file_encrypted -> file where we put the encryted data

def rsa_encrypt(data_to_encrypt, key_size=2048):
    #gera sozinho o private e public keys:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = generate_public_key(private_key)

    #cifrar o texto:
    cipher_text = public_key.encrypt(
        data_to_encrypt, 
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
        algorithm=hashes.SHA256(),
        label=None)
    )
    
    store_data(cipher_text, 'encryptacao.bin')
    store_key(private_key, 'chave_privada.pem')
    pass

def generate_private_key(size):
    return rsa.generate_private_key(public_exponent=65537, key_size=size)

def generate_public_key(private_key):
    return private_key.public_key()

def store_key(key, filename):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

def store_data(data_encrypted, filename):
    with open(filename, 'wb') as file:
        file.write(data_encrypted)

def read_data(filename):
    with open(filename, 'rb') as file:
        data = file.read()
    return data

def main(args):
    if len(args) < 2:
        print('Invalid argument')
        exit()

    # to generate the private key:
    data = read_data(args[1])
    rsa_encrypt(data)

    return 0

if __name__ == "__main__":
    main(sys.argv)