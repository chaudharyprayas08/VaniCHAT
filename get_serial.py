import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_cert_serial():
    print("--- SecureChat Serial Number Extractor ---")
    
    # 1. Ask for the certificate name
    cert_name = input("Enter the certificate name (e.g., peerA, peerB): ").strip()
    
    # 2. Construct the path
    # This assumes your certs are in the 'certs/' folder
    cert_path = f"certs/{cert_name}.crt"
    
    try:
        # 3. Load and parse the certificate
        if not os.path.exists(cert_path):
            print(f"❌ Error: Could not find file at {cert_path}")
            return

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # 4. Print the numeric serial number
        print(f"\n✅ Certificate: {cert_name}.crt")
        print(f"Numeric Serial Number: {cert.serial_number}")
        print("\nCopy the number above and paste it into manage_crl.py to revoke this user.")

    except Exception as e:
        print(f"❌ Error reading certificate: {e}")

if __name__ == "__main__":
    get_cert_serial()