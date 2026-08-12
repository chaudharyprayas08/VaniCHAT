import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import socket
import base64
import os
import json

from network.peer import SecurePeer


class SecureChatApp:

    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure P2P Chat")
        self.root.geometry("750x580")
        self.root.configure(bg="#1e1e2f")

        self.peer = None
        self.connected = False

        # -------------------------
        # Header
        # -------------------------
        header = tk.Label(
            root,
            text="Secure Peer-to-Peer Encrypted Chat",
            bg="#1e1e2f",
            fg="#00ffcc",
            font=("Segoe UI", 16, "bold")
        )
        header.pack(pady=10)

        # -------------------------
        # Connection Controls
        # -------------------------
        top_frame = tk.Frame(root, bg="#1e1e2f")
        top_frame.pack(pady=5)

        self.mode = tk.StringVar(value="listen")

        tk.Radiobutton(top_frame, text="Listen",
                       variable=self.mode, value="listen",
                       bg="#1e1e2f", fg="white",
                       selectcolor="#333").grid(row=0, column=0, padx=5)

        tk.Radiobutton(top_frame, text="Connect",
                       variable=self.mode, value="connect",
                       bg="#1e1e2f", fg="white",
                       selectcolor="#333").grid(row=0, column=1, padx=5)

        self.ip_entry = self.create_entry(top_frame, "127.0.0.1")
        self.ip_entry.grid(row=1, column=0, padx=5)

        self.port_entry = self.create_entry(top_frame, "5000", width=6)
        self.port_entry.grid(row=1, column=1, padx=5)

        self.name_entry = self.create_entry(top_frame, "user")
        self.name_entry.grid(row=1, column=2, padx=5)

        tk.Button(top_frame,
                  text="Start",
                  command=self.start_connection,
                  bg="#00b894",
                  fg="white",
                  relief=tk.FLAT,
                  padx=10).grid(row=1, column=3, padx=5)

        tk.Button(top_frame,
                  text="Close Session",
                  command=self.disconnect,
                  bg="#d63031",
                  fg="white",
                  relief=tk.FLAT,
                  padx=10).grid(row=1, column=4, padx=5)

        # -------------------------
        # Chat Area
        # -------------------------
        self.chat_area = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            height=20,
            bg="#2b2b3d",
            fg="white",
            font=("Segoe UI", 10),
            relief=tk.FLAT
        )
        self.chat_area.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)
        self.chat_area.config(state=tk.DISABLED)

        # -------------------------
        # Message + File Controls
        # -------------------------
        bottom_frame = tk.Frame(root, bg="#1e1e2f")
        bottom_frame.pack(pady=10)

        self.msg_entry = tk.Entry(
            bottom_frame,
            width=45,
            bg="#2b2b3d",
            fg="white",
            insertbackground="white",
            relief=tk.FLAT
        )
        self.msg_entry.pack(side=tk.LEFT, padx=5)

        tk.Button(bottom_frame,
                  text="Send",
                  command=self.send_message,
                  bg="#0984e3",
                  fg="white",
                  relief=tk.FLAT,
                  padx=15).pack(side=tk.LEFT)

        tk.Button(bottom_frame,
                  text="Send File",
                  command=self.send_file,
                  bg="#fd9644",
                  fg="white",
                  relief=tk.FLAT,
                  padx=10).pack(side=tk.LEFT, padx=5)

        # -------------------------
        # Status
        # -------------------------
        self.status_label = tk.Label(
            root,
            text="🔴 Not connected",
            fg="red",
            bg="#1e1e2f"
        )
        self.status_label.pack(pady=5)

    # -------------------------
    # Helper Entry
    # -------------------------
    def create_entry(self, parent, default_text="", width=15):
        entry = tk.Entry(parent,
                         width=width,
                         bg="#2b2b3d",
                         fg="white",
                         insertbackground="white",
                         relief=tk.FLAT)
        entry.insert(0, default_text)
        return entry

    # -------------------------
    # Start Connection
    # -------------------------
    def start_connection(self):
        name = self.name_entry.get()
        port = int(self.port_entry.get())
        mode = self.mode.get()
        ip = self.ip_entry.get()

        cert_path = f"certs/{name}.crt"
        key_path = f"certs/{name}.key"
        root_cert_path = "certs/rootCA.crt"

        self.peer = SecurePeer(name, cert_path, key_path, root_cert_path)

        threading.Thread(
            target=self.connect_thread,
            args=(mode, ip, port),
            daemon=True
        ).start()

    def connect_thread(self, mode, ip, port):
        try:
            if mode == "listen":
                self.peer.listen(port)
            else:
                self.peer.connect(ip, port)
            
            if self.peer.is_revoked():
             self.root.after(0, lambda: 
                self.status_label.config(text="❌ ACCESS DENIED: REVOKED", fg="#ff4757"))
             self.disconnect()
             return

            if not self.peer.secure_session:
                raise Exception("Handshake failed.")

            self.connected = True

            self.root.after(0, lambda:
                self.status_label.config(text="🟢 Securely Connected",
                                         fg="#00ffcc"))

            threading.Thread(target=self.receive_messages,
                             daemon=True).start()

        except Exception as e:
         error_msg = str(e)  # Capture the error string first
         self.root.after(0, lambda msg=error_msg: 
           messagebox.showerror("Connection Error", msg))

    # -------------------------
    # Disconnect
    # -------------------------
    def disconnect(self):
        if self.peer and self.peer.sock:
            try:
                self.peer.sock.shutdown(socket.SHUT_RDWR)
                self.peer.sock.close()
            except:
                pass

        self.connected = False
        self.peer = None

        self.status_label.config(text="🔴 Not connected", fg="red")
        self.display_message("System", "Session closed.", "red")

    # -------------------------
    # Receive Messages
    # -------------------------
    def receive_messages(self):
        while self.connected:
            try:
                data = self.peer.recv_framed()
                if not data:
                    break

                decrypted = self.peer.secure_session.decrypt(data)

                try:
                    message_obj = json.loads(decrypted)

                    if isinstance(message_obj, dict) and message_obj.get("type") == "file":
                        filename = message_obj["filename"]
                        file_bytes = base64.b64decode(message_obj["data"])

                        save_path = "received_" + filename

                        with open(save_path, "wb") as f:
                            f.write(file_bytes)

                        self.root.after(0, lambda:
                            self.display_message(
                                "System",
                                f"📁 File received and saved as {save_path}",
                                "#00ffcc"
                            ))
                        continue

                except:
                    pass

                self.root.after(0,
                    lambda msg=decrypted:
                    self.display_message("Peer", msg, "#6c5ce7"))

            except:
                break

        self.root.after(0, self.disconnect)

    # -------------------------
    # Send Text Message
    # -------------------------
    def send_message(self):
        message = self.msg_entry.get()

        if not message or not self.connected:
            return

        try:
            encrypted = self.peer.secure_session.encrypt(message)
            self.peer.send_framed(encrypted)

            self.display_message("You", message, "#00cec9")
            self.msg_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    # -------------------------
    # Send File
    # -------------------------
    def send_file(self):
        if not self.connected:
            messagebox.showerror("Error", "Not connected.")
            return

        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            payload = {
                "type": "file",
                "filename": os.path.basename(file_path),
                "data": base64.b64encode(file_data).decode()
            }

            encrypted = self.peer.secure_session.encrypt(json.dumps(payload))
            self.peer.send_framed(encrypted)

            self.display_message("You",
                                 f"📁 Sent file: {payload['filename']}",
                                 "#ffa502")

        except Exception as e:
            messagebox.showerror("File Send Error", str(e))

    # -------------------------
    # Display Message
    # -------------------------
    def display_message(self, sender, message, color):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"{sender}: {message}\n")
        self.chat_area.tag_config(sender, foreground=color)
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.see(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()