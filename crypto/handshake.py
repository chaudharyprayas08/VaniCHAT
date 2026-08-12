import os
import json
import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from crypto.cert_utils import check_revocation

from crypto.cert_utils import verify_certificate


# -----------------------------
# Utility Functions
# -----------------------------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode())


# -----------------------------
# Create Handshake Message
# -----------------------------

def create_hello_message(cert_path, key_path):
    # Load identity certificate
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()

    # Load private key
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Generate ephemeral ECDH key
    ephemeral_private = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )
    ephemeral_public = ephemeral_private.public_key()

    ephemeral_bytes = ephemeral_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    # Generate nonce
    nonce = os.urandom(32)

    # Sign ephemeral_public || nonce
    data_to_sign = ephemeral_bytes + nonce

    signature = private_key.sign(
        data_to_sign,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    message = {
        "type": "hello",
        "certificate": cert_bytes.decode(),
        "ephemeral_public_key": b64(ephemeral_bytes),
        "nonce": b64(nonce),
        "signature": b64(signature)
    }

    return json.dumps(message), ephemeral_private, nonce


# -----------------------------
# Process Peer Hello
# -----------------------------

def process_hello_message(
    message_json,
    root_cert,
    my_ephemeral_private,
    my_nonce,
    crl_path="certs/rootCA.crl"
):
    message = json.loads(message_json)

    if message["type"] != "hello":
        raise Exception("Invalid handshake message type.")

    # Load peer certificate
    peer_cert = x509.load_pem_x509_certificate(
        message["certificate"].encode(),
        default_backend()
    )

    # Verify certificate chain
    verify_certificate(peer_cert, root_cert)

    # Extract values
    peer_ephemeral_bytes = b64decode(message["ephemeral_public_key"])
    peer_nonce = b64decode(message["nonce"])
    peer_signature = b64decode(message["signature"])

    # Verify signature
    peer_public_key = peer_cert.public_key()
    data_signed = peer_ephemeral_bytes + peer_nonce

    try:
        peer_public_key.verify(
            peer_signature,
            data_signed,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception:
        raise Exception("Handshake signature verification failed.")

    # Load peer ephemeral public key
    peer_ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        peer_ephemeral_bytes
    )

    # Compute shared secret
    shared_secret = my_ephemeral_private.exchange(
        ec.ECDH(),
        peer_ephemeral_public
    )

    # Combine nonces deterministically (important!)
    if my_nonce < peer_nonce:
        combined_salt = my_nonce + peer_nonce
    else:
        combined_salt = peer_nonce + my_nonce
    check_revocation(peer_cert, root_cert, crl_path)
    # Derive session key
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=combined_salt,
        info=b"PSCP session key",
        backend=default_backend()
    ).derive(shared_secret)

    return session_key