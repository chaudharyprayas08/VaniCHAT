import os
import json
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode())


class SecureSession:

    def __init__(self, session_key: bytes):
        self.session_key = session_key
        self.send_seq = 0
        self.recv_seq = 0

    # -------------------------
    # Encrypt Message
    # -------------------------
    def encrypt(self, plaintext: str):

        self.send_seq += 1

        iv = os.urandom(12)  # 96-bit IV for GCM

        encryptor = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        aad = str(self.send_seq).encode()
        encryptor.authenticate_additional_data(aad)

        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

        message = {
            "type": "secure_message",
            "seq": self.send_seq,
            "iv": b64(iv),
            "ciphertext": b64(ciphertext),
            "tag": b64(encryptor.tag)
        }

        return json.dumps(message)

    # -------------------------
    # Decrypt Message
    # -------------------------
    def decrypt(self, message_json: str):

        message = json.loads(message_json)

        if message["type"] != "secure_message":
            raise Exception("Invalid secure message.")

        seq = message["seq"]

        # Replay protection
        if seq <= self.recv_seq:
            raise Exception("Replay attack detected.")

        iv = b64decode(message["iv"])
        ciphertext = b64decode(message["ciphertext"])
        tag = b64decode(message["tag"])

        decryptor = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        aad = str(seq).encode()
        decryptor.authenticate_additional_data(aad)

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        self.recv_seq = seq

        return plaintext.decode()