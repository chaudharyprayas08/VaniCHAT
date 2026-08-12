import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_root_ca():
    print("Generating Root CA private key...")

    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    # Subject and issuer are same (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jammu"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "IIT Jammu"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])

    print("Creating self-signed Root Certificate...")

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )
        .sign(private_key, hashes.SHA256())
    )

    # Create certs directory INSIDE CA
    certs_dir = os.path.join(os.path.dirname(__file__), "certs")
    os.makedirs(certs_dir, exist_ok=True)

    # Save private key
    key_path = os.path.join(certs_dir, "rootCA.key")
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save certificate
    cert_path = os.path.join(certs_dir, "rootCA.crt")
    with open(cert_path, "wb") as f:
        f.write(
            certificate.public_bytes(serialization.Encoding.PEM)
        )

    print("✅ Root CA generated successfully!")
    print("Private Key:", key_path)
    print("Certificate:", cert_path)


if __name__ == "__main__":
    generate_root_ca()