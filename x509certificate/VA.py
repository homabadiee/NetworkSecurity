import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.x509.base import CertificateSigningRequest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr, load_pem_x509_crl
import datetime


def generate_private_key():
    va_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open('va_private_key.pem', 'wb') as f:
        f.write(va_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return va_private_key

def generate_csr(private_key):
    csr = x509.CertificateSigningRequestBuilder() \
        .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'My VA'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'IT'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'VA'),
    ])) \
        .add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u'VA')]),
        critical=False,
    ) \
        .sign(private_key, hashes.SHA256())

    with open('va_csr.pem', 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr

def load_crl(crl_path):
    with open(crl_path, 'rb') as f:
        crl_data = f.read()
    return x509.load_pem_x509_crl(crl_data, default_backend())

def validate_certificate(certificate, crl):
    if certificate.issuer != crl.issuer:
        return 'False'

    revoked_certificate = crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
    if revoked_certificate is not None:
        return 'False'

    return 'True'

def va(certificate_to_validate, crl_path):
    crl = load_crl(crl_path)
    if not validate_certificate(certificate_to_validate, crl):
        print("Certificate is revoked")
    else:
        print("Certificate is valid")


# listen
def va_ssl():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_verify_locations('ca_cert.pem')
    context.load_cert_chain(certfile='va_cert.pem', keyfile='va_private_key.pem')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 4545))
    sock.listen(1)

    while True:
        # Accept incoming connection
        conn, addr = sock.accept()

        # Wrap socket with SSL
        ssl_conn = context.wrap_socket(conn, server_side=True)

        # Receive client's certificate
        # client_certificate_bytes = ssl_conn.getpeercert(True)
        # client_certificate = x509.load_pem_x509_certificate(client_certificate_bytes, default_backend())

        with open('client1_cert.pem', 'rb') as cert_file:
            client_certificate = load_pem_x509_certificate(
                cert_file.read(),
                backend=default_backend()
            )

        # Validate client's certificate
        with open('crl.pem', 'rb') as f:
            crl = load_pem_x509_crl(f.read(), default_backend())
        result = validate_certificate(client_certificate, crl)

        # Send validation result
        ssl_conn.send(result.encode())

        # Close connection
        ssl_conn.close()


####### FIRST PART ########
# generate private key and csr
# va_private_key = generate_private_key()
# va_csr = generate_csr(va_private_key)

####### SECOND PART ########
va_ssl()

