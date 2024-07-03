import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_certificate


def generate_private_key():
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open('client2_private_key.pem', 'wb') as f:
        f.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return client_private_key

def generate_csr(private_key):
    csr = x509.CertificateSigningRequestBuilder() \
        .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Client2'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'IT'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'Client2'),
    ])) \
        .add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u'Client2')]),
        critical=False,
    ) \
        .sign(private_key, hashes.SHA256())

    with open('client2_csr.pem', 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr


def client_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 12345))

    # Send data to RA server
    username = input("Enter username: ")
    password = input("Enter password: ")
    cert_path = 'client2_cert.pem'
    csr_path = 'client2_csr.pem'
    data = f"{username}:{password}:{cert_path}:{csr_path}".encode("utf-8")
    sock.send(data)

    # Receive data from RA server
    data = sock.recv(1024)

    if data.decode("utf-8") == "success":
        print("Authentication successful")
    else:
        print("Authentication failed")
    sock.close()


def va_validate_certificate(certificate):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('ca_cert.pem')
    context.load_cert_chain(certfile='client2_cert.pem', keyfile='client2_private_key.pem')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to client2 server
    ssl_sock = context.wrap_socket(sock, server_hostname='VA')
    ssl_sock.connect(('localhost', 4545))

    certificate_bytes = certificate.public_bytes(Encoding.PEM)

    # Send certificate
    ssl_sock.send(certificate_bytes)

    # Receive client2's certificate
    result = ssl_sock.recv(1024)

    # Close connection
    ssl_sock.close()

    print(result)
    if result == b'True':
        return True
    else:
        return False




# listen
def client2_listen_ssl(client2_certificate):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_verify_locations('ca_cert.pem')
    context.load_cert_chain(certfile='client2_cert.pem', keyfile='client2_private_key.pem')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 12345))
    sock.listen(1)
    while True:
        conn, addr = sock.accept()
        ssl_conn = context.wrap_socket(conn, server_side=True)
        client1_certificate_bytes = ssl_conn.recv(1024)
        # client1_certificate = x509.load_pem_x509_certificate(client1_certificate_bytes, default_backend())
        with open('client1_cert.pem', 'rb') as cert_file:
            client1_certificate = load_pem_x509_certificate(
                cert_file.read(),
                backend=default_backend()
            )
        if va_validate_certificate(client1_certificate):
            print('Certificate Validated Successfully')
            client2_certificate_bytes = client2_certificate.public_bytes(serialization.Encoding.PEM)
            ssl_conn.send(client2_certificate_bytes)
        else:
            print('Certificate Validation Failed')

        ssl_conn.close()

####### FIRST PART ########
# generate private key and csr
# client_private_key = generate_private_key()
# client_csr = generate_csr(client_private_key)


####### SECOND PART ########
# use previous private key
# with open('client2_private_key.pem', 'rb') as key_file:
#     client_private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#         backend=default_backend()
#     )
#
# client_socket()

####### THIRD PART ########
with open('client2_cert.pem', 'rb') as cert_file:
    client_cert = load_pem_x509_certificate(
        cert_file.read(),
        backend=default_backend()
    )
client2_listen_ssl(client_cert)

