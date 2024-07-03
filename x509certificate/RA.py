import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.x509.base import CertificateSigningRequest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr


def generate_private_key():
    ra_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open('ra_private_key.pem', 'wb') as f:
        f.write(ra_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return ra_private_key

def generate_csr(private_key):
    csr = x509.CertificateSigningRequestBuilder() \
        .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'My RA'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'IT'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'RA'),
    ])) \
        .add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u'RA')]),
        critical=False,
    ) \
        .sign(private_key, hashes.SHA256())

    with open('ra_csr.pem', 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr

def user_authentication(username, password):
    with open('db.txt', 'r') as db_file:
        for line in db_file:
            fields = line.strip().split(':')
            if fields[0] == username and fields[1] == password:
                return True

    return False

def CA_sign_certificate(csr_path, output_cert_path):
    # Generate the certificate signing the CSR with the CA's private key
    with open('ca_private_key.pem', 'rb') as key_file:
        ca_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    with open(csr_path, 'rb') as f:
        csr_data = f.read()
    csr = load_pem_x509_csr(csr_data, default_backend())

    with open('ca_cert.pem', 'rb') as cert_file:
        ca_cert = load_pem_x509_certificate(
            cert_file.read(),
            backend=default_backend()
        )

    certificate = x509.CertificateBuilder()\
        .subject_name(csr.subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(csr.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(ca_cert.not_valid_before_utc)\
        .not_valid_after(ca_cert.not_valid_after_utc)\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .sign(ca_private_key, hashes.SHA256(), default_backend())

    with open(output_cert_path, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    with open(output_cert_path.split('.')[0] + '.crt', 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.DER))

    return certificate

def RA_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("localhost", 12345))
    sock.listen(1)

    while True:
        conn, addr = sock.accept()
        data = conn.recv(1024)
        data_str = data.decode("utf-8")
        username, password, cert_path, csr_path = data_str.split(":")
        if user_authentication(username, password):
            CA_sign_certificate(csr_path, cert_path)
            conn.sendall(b"success")
        else:
            conn.sendall(b"failure")
        conn.close()


####### FIRST PART ########
# generate private key and csr
# ra_private_key = generate_private_key()
# ra_csr = generate_csr(ra_private_key)


####### SECOND PART ########
# use previous private key and signed certificate
with open('ra_private_key.pem', 'rb') as key_file:
    ra_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open('ra_cert.pem', 'rb') as cert_file:
    ca_cert = load_pem_x509_certificate(
        cert_file.read(),
        backend=default_backend()
    )

RA_socket()


