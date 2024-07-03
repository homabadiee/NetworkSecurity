from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_crl

def generate_private_key():
    root_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    with open('ca_private_key.pem', 'wb') as f:
        f.write(root_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return root_private_key

def generate_root_certificate(ca_private_key):
    ca_public_key = ca_private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'My Company'),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Root CA'),
    ]))
    builder = builder.issuer_name(x509.Name([
        # its issuer is itself
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'My Company'),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Root CA'),
    ]))
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=10*365))  # Valid for 10 years
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ca_public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    # Self-sign our certificate
    ca_certificate = builder.sign(
        private_key=ca_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    with open('ca_cert.pem', 'wb') as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

    with open('ca_cert.crt', 'wb') as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.DER))

    return ca_certificate

def create_crl(ca_private_key, ca_cert):
    now = datetime.utcnow()
    next_update = now + timedelta(days=7)

    crl_builder = x509.CertificateRevocationListBuilder().issuer_name(
        ca_cert.subject
    ).last_update(
        now
    ).next_update(
        next_update
    )

    crl = crl_builder.sign(ca_private_key, hashes.SHA256(), default_backend())

    with open('crl.pem', 'wb') as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    return crl

def update_crl(ca_private_key, revoked_cert_path):
    cert_to_revoke_data = open(revoked_cert_path, 'rb').read()
    cert_to_revoke = x509.load_pem_x509_certificate(cert_to_revoke_data, backend=default_backend())
    with open('crl.pem', 'rb') as f:
        crl = load_pem_x509_crl(f.read(), default_backend())
    # generate a new crl object
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(crl.issuer)
    builder = builder.last_update(crl.last_update_utc)
    builder = builder.next_update(datetime.now() + timedelta(days=7))
    # add crl certificates from file to the new crl object
    for i in range(0, len(crl)):
        builder = builder.add_revoked_certificate(crl[i])
    # see if the cert to be revoked already in the list
    ret = crl.get_revoked_certificate_by_serial_number(cert_to_revoke.serial_number)

    # if not, then add new revoked cert
    if not isinstance(ret, x509.RevokedCertificate):
        revoked_cert = x509.RevokedCertificateBuilder() \
            .serial_number(cert_to_revoke.serial_number) \
            .revocation_date(datetime.now()).build(backend=default_backend())

        builder = builder.add_revoked_certificate(revoked_cert)

    # sign and save to new crl file
    cert_revocation_list = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())

    with open('crl.crl', 'wb') as f:
        f.write(cert_revocation_list.public_bytes(serialization.Encoding.PEM))

    with open('crl.pem', 'wb') as f:
        f.write(cert_revocation_list.public_bytes(serialization.Encoding.PEM))


def sign_certificate(csr, ca_private_key, ca_cert, output_cert_path):
    # Generate the certificate signing the CSR with the CA's private key
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


####### FIRST PART ########
# generate private key and certificate
# ca_private_key = generate_private_key()
# ca_cert = generate_root_certificate(ca_private_key)
# create_crl(ca_private_key, ca_cert)

####### SECOND PART ########
# use previous private key and certificate
# with open('ca_private_key.pem', 'rb') as key_file:
#     ca_private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#         backend=default_backend()
#     )
#
# with open('ca_cert.pem', 'rb') as cert_file:
#     ca_cert = load_pem_x509_certificate(
#         cert_file.read(),
#         backend=default_backend()
#     )
#
# with open('ra_csr.pem', 'rb') as csr_file:
#     csr_data = csr_file.read()
#     ra_csr = x509.load_pem_x509_csr(csr_data, default_backend())
#
# with open('va_csr.pem', 'rb') as csr_file:
#     csr_data = csr_file.read()
#     va_csr = x509.load_pem_x509_csr(csr_data, default_backend())
#
# sign_certificate(ra_csr, ca_private_key, ca_cert, 'ra_cert.pem')
# sign_certificate(va_csr, ca_private_key, ca_cert, 'va_cert.pem')


####### THIRD PART ########
with open('ca_private_key.pem', 'rb') as key_file:
    ca_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
update_crl(ca_private_key, 'client1_cert.pem')
