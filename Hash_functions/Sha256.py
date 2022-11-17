import sys
from cryptography.hazmat.primitives import hashes

# inputs:  name of file with the data
# nam of cryptofraphic hash function to use 
# print the hash in the screen or console
# hex format

def compare_hashes(h1, h2):
    comp = int.from_bytes(h1, sys.byteorder) ^ int.from_bytes(h2, sys.byteorder)
    return bin(comp)[2:].count("0")

def read_data(filename):
    with open(filename, 'rb') as file:
        data = file.read()
    return data

def flip_bit(data):
    adata = bytearray(data)
    adata[0] = adata[0]^0x80
    return adata

def to_hash(data, hash_function = "MD5"):
    digest = hashes.Hash(hashes.SHA256())

    if hash_function.lower() == "Sha256".lower():
        digest = hashes.Hash(hashes.SHA256())

    if hash_function.lower() == "MD5".lower():
        digest = hashes.Hash(hashes.MD5())
    
    if hash_function.lower() == "Sha384".lower():
        digest = hashes.Hash(hashes.SHA384())

    if hash_function.lower() == "Sha512".lower():
        digest = hashes.Hash(hashes.SHA512())

    if hash_function.lower() == "Blake".lower():
        digest = hashes.Hash(hashes.BLAKE2b())

    digest.update(data)
    data_hashed = digest.finalize()
    return data_hashed


def main(args):
    if len(args) < 2:
        print('Invalid argument')
        exit()

    hash_function = "Sha256"
    nome_ficheiro = args[1]

    if len(args) > 2:
        hash_function = args[2]

    data = read_data(nome_ficheiro)
    hashed_data = to_hash(data, hash_function)
    print("Normal hashed data: ")
    print(hashed_data.hex())

    new_data = flip_bit(data)
    hashed_data_shifted = to_hash(new_data, hash_function)
    print("Shifted hashed data:")
    print(hashed_data_shifted.hex())

    print("Comparing hashes:")
    equal_bits = compare_hashes(hashed_data, hashed_data_shifted)
    print(equal_bits)

    return 0

if __name__ == "__main__":
    main(sys.argv)