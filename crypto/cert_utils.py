import datetime

from cryptography import x509

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.backends import default_backend
import os





def load_certificate(path):

    with open(path, "rb") as f:

        return x509.load_pem_x509_certificate(f.read(), default_backend())





def verify_certificate(peer_cert: x509.Certificate, root_cert: x509.Certificate):

    """

    Verifies:

    - Signature by Root CA

    - Validity period

    - BasicConstraints

    - KeyUsage

    """



    # 1️⃣ Verify signature

    root_public_key = root_cert.public_key()



    try:

        root_public_key.verify(

            peer_cert.signature,

            peer_cert.tbs_certificate_bytes,

            padding.PKCS1v15(),

            peer_cert.signature_hash_algorithm,

        )

    except Exception as e:

        raise Exception("Certificate signature verification failed.") from e



    # 2️⃣ Check validity period

    # now = datetime.datetime.utcnow()



    # if now < peer_cert.not_valid_before or now > peer_cert.not_valid_after:

    #     raise Exception("Certificate expired or not yet valid.")

    now = datetime.datetime.now(datetime.timezone.utc)



    if now < peer_cert.not_valid_before_utc or now > peer_cert.not_valid_after_utc:

        raise Exception("Certificate expired or not yet valid.")



    # 3️⃣ Check BasicConstraints

    try:

        basic_constraints = peer_cert.extensions.get_extension_for_class(

            x509.BasicConstraints

        ).value



        if basic_constraints.ca:

            raise Exception("Peer certificate cannot be a CA.")

    except x509.ExtensionNotFound:

        raise Exception("BasicConstraints missing.")



    # 4️⃣ Check KeyUsage

    try:

        key_usage = peer_cert.extensions.get_extension_for_class(

            x509.KeyUsage

        ).value



        if not key_usage.digital_signature:

            raise Exception("Certificate not allowed for digital signature.")

    except x509.ExtensionNotFound:

        raise Exception("KeyUsage missing.")

   

    return True





def get_certificate_fingerprint(cert: x509.Certificate):

    return cert.fingerprint(hashes.SHA256()).hex()
def check_revocation(peer_cert, root_cert, crl_path="certs/rootCA.crl"):
    """
    Returns True if the certificate is safe. 
    Raises an Exception if it is revoked.
    """
    if not os.path.exists(crl_path):
        return True # If no CRL exists, assume no one is revoked yet
        
    with open(crl_path, "rb") as f:
        crl = x509.load_pem_x509_crl(f.read(), default_backend())
    
    # Verify the CRL signature to ensure it's from YOUR Root CA
    crl.is_signature_valid(root_cert.public_key())
    
    # Check if the peer's serial number is on the blacklist
    if crl.get_revoked_certificate_by_serial_number(peer_cert.serial_number):
        raise Exception("REVOKED: Peer certificate is blacklisted.")
    
    return True