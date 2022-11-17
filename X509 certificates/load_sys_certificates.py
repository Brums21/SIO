import os
from cryptography import x509

def load_system_certs(cert_path):
    certs = {}
    obj = os.scandir(cert_path)

    for entry in obj:
        if entry.name.endswith('.pem'):
            with open(entry.path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                certs[cert.subject] = cert
    return certs

if __name__ == "__main__":
    cert_path = '/etc/ssl/certs'
    if os.path.exists(cert_path):
        system_certs = load_system_certs(cert_path)
        print(len(system_certs))