import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

CA_IP = "192.168.1.10"   # CHANGE THIS
CA_PORT = 9000

PEER_PORT = 9001


class ClientGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Secure Client PKI")

        tk.Label(root, text="Your Name").pack()
        self.name_entry = tk.Entry(root)
        self.name_entry.pack()

        tk.Label(root, text="Peer IP").pack()
        self.peer_ip_entry = tk.Entry(root)
        self.peer_ip_entry.pack()

        tk.Button(root, text="Generate Key", command=self.generate_key).pack(pady=3)
        tk.Button(root, text="Request Certificate (CA)", command=self.request_cert).pack(pady=3)
        tk.Button(root, text="Verify My Certificate", command=self.verify_cert).pack(pady=3)

        tk.Button(root, text="Start Peer Server", command=self.start_peer_server).pack(pady=3)
        tk.Button(root, text="Send My Certificate To Peer", command=self.send_cert_to_peer).pack(pady=3)
        tk.Button(root, text="Verify Received Peer Certificate", command=self.verify_peer_cert).pack(pady=3)

        self.log = scrolledtext.ScrolledText(root, width=60, height=10)
        self.log.pack(pady=5)

    def log_message(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def get_name(self):
        return self.name_entry.get()

    # ------------------ KEY GENERATION ------------------

    def generate_key(self):
        name = self.get_name()

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )

        with open(f"certs/{name}.key", "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                )
            )

        self.log_message("Key generated")

    # ------------------ REQUEST CERT FROM CA ------------------

    def request_cert(self):
        name = self.get_name()

        with open(f"certs/{name}.key", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), None)

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, name)
                ])
            )
            .sign(private_key, hashes.SHA256())
        )

        s = socket.socket()
        s.connect((CA_IP, CA_PORT))
        s.send(csr.public_bytes(serialization.Encoding.PEM))

        cert_data = s.recv(10000)
        s.close()

        with open(f"certs/{name}.crt", "wb") as f:
            f.write(cert_data)

        self.log_message("Certificate received from CA")

    # ------------------ VERIFY OWN CERT ------------------

    def verify_cert(self):
        name = self.get_name()

        with open("certs/rootCA.crt", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        with open(f"certs/{name}.crt", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        try:
            root_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            self.log_message("My Certificate Verified")
        except:
            self.log_message("Verification Failed")

    # ------------------ PEER SERVER ------------------

    def start_peer_server(self):
        def server():
            sock = socket.socket()
            sock.bind(("0.0.0.0", PEER_PORT))
            sock.listen(5)
            self.log_message("Peer Server Started")

            while True:
                conn, addr = sock.accept()
                data = conn.recv(10000)

                with open("certs/peer_received.crt", "wb") as f:
                    f.write(data)

                self.log_message(f"Received certificate from {addr}")
                conn.close()

        threading.Thread(target=server, daemon=True).start()

    # ------------------ SEND CERT TO PEER ------------------

    def send_cert_to_peer(self):
        peer_ip = self.peer_ip_entry.get()
        name = self.get_name()

        with open(f"certs/{name}.crt", "rb") as f:
            cert_data = f.read()

        s = socket.socket()
        s.connect((peer_ip, PEER_PORT))
        s.send(cert_data)
        s.close()

        self.log_message("Certificate sent to peer")

    # ------------------ VERIFY PEER CERT ------------------

    def verify_peer_cert(self):
        with open("certs/rootCA.crt", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        with open("certs/peer_received.crt", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        try:
            root_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            self.log_message("Peer Certificate Verified")
        except:
            self.log_message("Peer Certificate Invalid")


root = tk.Tk()
ClientGUI(root)
root.mainloop()