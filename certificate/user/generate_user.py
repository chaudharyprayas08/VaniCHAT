import os
import datetime
import secrets
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Custom OID for our Nonce extension
NONCE_OID = ObjectIdentifier("1.2.3.4.5.6.7.8.1")

def generate_user():
    # 1. Generate the RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend()
    )

    os.makedirs("certs", exist_ok=True)

    # 2. Save private key locally
    with open("certs/user.key", "wb") as f:
        f.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )

    # 3. Generate random 128-bit nonce and timestamp
    nonce = secrets.token_hex(16)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 4. Create the Certificate Signing Request (CSR)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat User"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PeerA"),
        ]))
        .add_extension(
            x509.UnrecognizedExtension(NONCE_OID, nonce.encode()),
            critical=False
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # 5. Save CSR for the Root CA
    with open("certs/user.csr", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    # 6. LOG only the nonce and time locally
    with open("user_request_log.txt", "a") as f:
        f.writelines([
            f"\n--- Request Sent: {timestamp} ---\n",
            f"Sent Nonce: {nonce}\n",
            f"------------------------------\n"
        ])

    print("✅ CSR generated and saved to certs/user.csr.")
    print(f"✅ Nonce logged to user_request_log.txt: {nonce}")

if __name__ == "__main__":
    generate_user()