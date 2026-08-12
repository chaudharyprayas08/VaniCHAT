import socket
import struct
import json
import os

from crypto.handshake import create_hello_message, process_hello_message
from crypto.cert_utils import load_certificate
from crypto.session import SecureSession
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SecurePeer:

    def __init__(self, name, cert_path, key_path, root_cert_path):
        self.name = name
        self.cert_path = cert_path
        self.key_path = key_path
        self.root_cert = load_certificate(root_cert_path)

        self.sock = None
        self.session_key = None
        self.secure_session = None

    # -------------------------
    # LISTEN
    # -------------------------
    def listen(self, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", port))
        server.listen(1)

        conn, _ = server.accept()
        self.sock = conn

        self.perform_handshake(is_initiator=False)

    # -------------------------
    # CONNECT
    # -------------------------
    def connect(self, host, port):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        self.sock = client

        self.perform_handshake(is_initiator=True)

    # -------------------------
    # HANDSHAKE (FRAMED)
    # -------------------------
    def perform_handshake(self, is_initiator):

        my_hello, my_ephemeral, my_nonce = create_hello_message(
            self.cert_path,
            self.key_path
        )

        if is_initiator:
            self.send_framed(my_hello)
            peer_hello = self.recv_framed()
        else:
            peer_hello = self.recv_framed()
            self.send_framed(my_hello)
        msg_obj = json.loads(peer_hello)
        self.peer_cert = x509.load_pem_x509_certificate(
         msg_obj["certificate"].encode(), 
         default_backend()
    )

        self.session_key = process_hello_message(
            peer_hello,
            self.root_cert,
            my_ephemeral,
            my_nonce,
            crl_path="certs/rootCA.crl"
        )

        self.secure_session = SecureSession(self.session_key)

    # -------------------------
    # Framing Functions
    # -------------------------
    def send_framed(self, message: str):
        data = message.encode()
        length = struct.pack(">I", len(data))
        self.sock.sendall(length + data)

    def recv_framed(self):
        raw_len = self.recv_exact(4)
        if not raw_len:
            return None

        msg_len = struct.unpack(">I", raw_len)[0]
        return self.recv_exact(msg_len).decode()

    def recv_exact(self, n):
        data = b""
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data
    def is_revoked(self):
     crl_path = "certs/rootCA.crl"
     if not os.path.exists(crl_path):
        return False # No CRL exists yet

     with open(crl_path, "rb") as f:
        crl = x509.load_pem_x509_crl(f.read(), default_backend())

    # Peer certificate is received during handshake
    # Check if the serial number is blacklisted
     revoked = crl.get_revoked_certificate_by_serial_number(self.peer_cert.serial_number)
     return revoked is not None