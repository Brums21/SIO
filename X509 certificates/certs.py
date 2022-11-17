import datetime
import os
from cryptography import x509
import click

def load_certificates(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)

def check_validity(cert):
    if cert.not_valid_before <= datetime.datetime.now() and cert.not_valid_after >= datetime.datetime.now():
        print("Certificate is valid")
        return 1
    else:
        print("Certificate is not valid")
        return 0


def validate_chain(cert, roots):
    if not check_validity(cert):
        return False
    
    if cert.issuer != cert.subject:
        return validate_chain(roots[cert.issuer])
    else:
        return check_validity(cert)


def iterative_validate_chain(cert, imcert, roots):
    if not check_validity(cert):
        return False

    if cert.issuer != imcert.subject:
        return False

    if not check_validity(imcert):
        return False
    
    if roots[imcert.issuer]:
        return check_validity(roots[imcert.issuer])
    
    return False

def load_system_certs(cert_path):
    certs = {}
    obj = os.scandir(cert_path)

    for entry in obj:
        if entry.name.endswith('.pem'):
            with open(entry.path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                certs[cert.subject] = cert
    return certs

def exercicio1(certfile):
    if not os.path.exists(certfile):
        print('File not found')
        exit(1)

    cert = load_certificates(certfile)
    check_validity(cert)
    print(cert)

def exercicio2():
    cert_path = '/etc/ssl/certs'
    if os.path.exists(cert_path):
        system_certs = load_system_certs(cert_path)
        print(len(system_certs))
        return system_certs
    return None

def exercicio3(imcertfile, cert, system_certs):   

    # Validar certification path
    if imcertfile:
        imcert = load_certificates(imcertfile)
        if iterative_validate_chain(cert, imcert, system_certs):
            print("Chain validated.")
        else:
            print("Chain not validated.")
    else:
        if validate_chain(cert, system_certs):
            print("Chain validated.")
        else:
            print("Chain not validated.")

@click.command()
@click.option('--certfile', required=True, help = 'Certificate file to validate')
@click.option('--imcertfile', default = None, help='IM file to certificate')

def main(certfile, imcertfile):
    
    cert = exercicio1(certfile)
    system_certs = exercicio2()
    exercicio3(imcertfile, cert, system_certs)




if __name__ == "__main__":
    main()