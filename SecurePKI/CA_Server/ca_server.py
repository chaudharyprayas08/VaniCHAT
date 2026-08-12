import socket
import threading
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

HOST = "0.0.0.0"
PORT = 9000


def handle_client(conn):
    try:
        print("[*] Receiving CSR...")

        csr_data = conn.recv(10000)

        csr = x509.load_pem_x509_csr(csr_data)

        if not csr.is_signature_valid:
            conn.send(b"CSR Signature Invalid")
            conn.close()
            return

        print("[+] CSR verified")

        # Load CA key and cert
        with open("certs/rootCA.key", "rb") as f:
            root_key = serialization.load_pem_private_key(f.read(), None)

        with open("certs/rootCA.crt", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(root_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(root_key, hashes.SHA256())
        )

        conn.send(certificate.public_bytes(serialization.Encoding.PEM))
        print("[+] Certificate sent")

    except Exception as e:
        print("Error:", e)

    finally:
        conn.close()


def start_server():
    server = socket.socket()
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[+] CA Server running on port {PORT}")

    while True:
        conn, addr = server.accept()
        print(f"[+] Connection from {addr}")
        threading.Thread(target=handle_client, args=(conn,)).start()


if __name__ == "__main__":
    start_server()