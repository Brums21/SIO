from email.policy import default
import sys
from  cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# data_to_encrypt -> data that we are gonna encrypt
# public_key -> data that contains the public key
# file_encrypted -> file where we put the encryted data

def rsa_decrypt(data_to_decrypt, private_key, key_size=2048):

    #decifrar o texto:
    texto = private_key.decrypt(
        data_to_decrypt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
    ))
    
    store_data(texto, 'texto_desencriptado.txt')
    pass

def read_private_key(filename):
    with open(filename, 'rb') as privatefile:
        key_bytes = privatefile.read()
    key = serialization.load_pem_private_key(key_bytes, password=None)
    return key

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

    # ler o ficheiro e ler a chave publica (ficheiro .pem)
    # to generate the private key:
    ficheiro = args[1]
    chave_privada = read_private_key(args[2])        
    data = read_data(ficheiro)                 
    rsa_decrypt(data, chave_privada)

    return 0

if __name__ == "__main__":
    main(sys.argv)