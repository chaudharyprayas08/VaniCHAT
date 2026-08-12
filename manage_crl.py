import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def create_crl(revoked_serials, ca_cert_path, ca_key_path, output_path):
    # Load CA Private Key
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # Load CA Certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))

    # Add each serial number to the list
    for serial in revoked_serials:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            serial
        ).revocation_date(datetime.datetime.now(datetime.timezone.utc)).build()
        builder = builder.add_revoked_certificate(revoked_cert)

    # Sign the CRL
    crl = builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    with open(output_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    print(f"CRL successfully generated at {output_path}")
if __name__ == "__main__":
    # Define paths based on your folder structure
    CA_CERT = "certs/rootCA.crt"
    CA_KEY = "certs/rootCA.key"
    CRL_OUTPUT = "certs/rootCA.crl"

    print("--- SecureChat CRL Manager ---")
    try:
        # Ask the user for the serial number
        raw_serial = input("Enter the Serial Number to revoke: ").strip()
        
        # Convert the string input to an integer for the builder
        serial_to_revoke = int(raw_serial)
        
        # Generate the CRL
        create_crl(
            [serial_to_revoke], 
            CA_CERT, 
            CA_KEY, 
            CRL_OUTPUT
        )
        
        print(f"✅ Success! Serial {serial_to_revoke} has been added to the CRL.")
        print(f"Next Step: Email {CRL_OUTPUT} to all other peers.")

    except ValueError:
        print("❌ Error: Please enter a valid numeric serial number.")
    except FileNotFoundError:
        print(f"❌ Error: Could not find CA files in {CA_CERT} or {CA_KEY}.")
# Example usage for your demo:
# create_crl([123456789], "certs/rootCA.crt", "certs/rootCA.key", "certs/rootCA.crl")