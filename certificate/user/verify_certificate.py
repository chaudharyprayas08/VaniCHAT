import hashlib
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Custom OID for our Nonce extension
NONCE_OID = ObjectIdentifier("1.2.3.4.5.6.7.8.1")

def verify_and_log():
    try:
        # 1. Check if all required files exist
        required_files = ["certs/rootCA.crt", "certs/user.crt", "certs/response.sig"]
        for file in required_files:
            if not os.path.exists(file):
                print(f"❌ Error: Missing {file}")
                return

        # 2. Load the Root CA certificate
        with open("certs/rootCA.crt", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # 3. Load the User certificate
        with open("certs/user.crt", "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # 4. Load the detached signature (response.sig)
        with open("certs/response.sig", "rb") as f:
            signature = f.read()

        # 5. STEP ONE: Verify the detached signature
        # This confirms user.crt matches what the CA signed
        root_cert.public_key().verify(
            signature,
            user_cert.public_bytes(serialization.Encoding.PEM),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("✅ CA Detached Signature (response.sig) verified.")

        # 6. STEP TWO: Verify the internal certificate chain
        root_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm,
        )
        print("✅ Internal Certificate chain verified.")

        # 7. Extract Nonce from certificate extension
        nonce_extension = user_cert.extensions.get_extension_for_oid(NONCE_OID)
        extracted_nonce = nonce_extension.value.value.decode()

        # 8. Calculate OTP from the Public Key
        public_key_bytes = user_cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        calculated_otp = hashlib.sha256(public_key_bytes).hexdigest()[:6]

        # 9. LOG the verification details
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("user_request_log.txt", "a") as f:
            f.writelines([
                f"\n--- Verification: {timestamp} ---\n",
                f"Extracted Nonce: {extracted_nonce}\n",
                f"Calculated OTP: {calculated_otp}\n",
                f"Status: Verified (Full Chain + Sig)\n",
                f"------------------------------\n"
            ])

        print(f"✅ Success! Extracted Nonce: {extracted_nonce}")
        print(f"✅ Success! Calculated OTP: {calculated_otp}")
        print("✅ Results appended to user_request_log.txt")

    except Exception as e:
        print(f"❌ Verification FAILED: {e}")

if __name__ == "__main__":
    verify_and_log()