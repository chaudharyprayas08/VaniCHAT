import datetime
import hashlib
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Custom OID for our Nonce extension
NONCE_OID = ObjectIdentifier("1.2.3.4.5.6.7.8.1")

# 1. Load root CA Private Key and Certificate
with open("certs/rootCA.key", "rb") as f:
    root_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

with open("certs/rootCA.crt", "rb") as f:
    root_cert = x509.load_pem_x509_certificate(
        f.read(),
        default_backend()
    )

# 2. Load the incoming CSR (e.g., emailed from Peer A)
with open("certs/user.csr", "rb") as f:
    csr = x509.load_pem_x509_csr(f.read(), default_backend())

if not csr.is_signature_valid:
    raise Exception("Invalid CSR signature!")

# 3. Extract the Nonce extension
nonce_extension = csr.extensions.get_extension_for_oid(NONCE_OID)
nonce = nonce_extension.value.value

# 4. Generate the signed Certificate
certificate = (
    x509.CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(root_cert.subject)
    .public_key(csr.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.UnrecognizedExtension(NONCE_OID, nonce),
        critical=False
    )
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None), 
        critical=True
    )
    # ADDED THIS: Explicitly grant permissions to the user certificate
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,    # Allows handshake proof
            content_commitment=False,
            key_encipherment=True,     # Allows session key exchange
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,       # User CANNOT sign other certs
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    )
    .sign(root_key, hashes.SHA256(), default_backend())
)

# 5. Save the final certificate
with open("user.crt", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

# 6. Generate the 6-digit OTP and Log Issuance
timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Extract the Public Key from the cert to generate the OTP
cert_public_key = certificate.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
# This matches the logic in Peer A's generate_user.py
issued_otp = hashlib.sha256(cert_public_key).hexdigest()[:6]

# Save to the CA side log file
peer_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
with open("ca_issuance_log.txt", "a") as f:
    f.writelines([
        f"\n--- Issued to {peer_name} at {timestamp} ---\n",
        f"OTP: {issued_otp}\n",
        f"Serial: {certificate.serial_number}\n",
        f"--------------------------------------\n"
    ])

print(f"Certificate signed for {peer_name}.")
print(f"Issued OTP: {issued_otp}")
print(f"Issuance logged to ca_issuance_log.txt")

# 7. Sign the certificate package for the response
cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
signature = root_key.sign(
    cert_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)

with open("response.sig", "wb") as f:
    f.write(signature)

print("Signature file 'response.sig' created.")