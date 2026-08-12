import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import socket
import base64
import os
import json

# Importing the backend peer logic
from network.peer import SecurePeer

class SecureChatApp:

    def __init__(self, root):
        self.root = root
        self.root.title("VANI | Secure P2P")
        self.root.geometry("500x750") 
        self.root.configure(bg="#0f172a") # Dark background

        self.peer = None
        self.connected = False

        # --- Advanced Color Palette (From App 1) ---
        self.colors = {
            "bg": "#020617",         
            "header": "#1e293b",     
            "accent": "#38bdf8",     
            "my_bubble": "#0284c7",   
            "peer_bubble": "#1e293b", 
            "text": "#f8fafc",
            "system": "#94a3b8",
            "danger": "#ef4444",
            "success": "#22c55e"
        }

        self.setup_ui()

    def setup_ui(self):
        # Header Section
        header_frame = tk.Frame(self.root, bg=self.colors["bg"], pady=10)
        header_frame.pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="VANI | Secure P2P",
            bg=self.colors["bg"],
            fg=self.colors["accent"],
            font=("Inter", 18, "bold")
        ).pack()

        self.status_label = tk.Label(
            header_frame,
            text="● Offline",
            fg=self.colors["danger"],
            bg=self.colors["bg"],
            font=("Inter", 9)
        )
        self.status_label.pack()

        # Configuration Panel
        config_frame = tk.Frame(self.root, bg=self.colors["header"], padx=15, pady=15)
        config_frame.pack(padx=15, pady=10, fill=tk.X)

        self.mode = tk.StringVar(value="listen")

        radio_style = {"bg": self.colors["header"], "fg": "white", "selectcolor": "#020617", "activebackground": self.colors["header"]}
        tk.Radiobutton(config_frame, text="Host Session", variable=self.mode, value="listen", **radio_style).grid(row=0, column=0, padx=5)
        tk.Radiobutton(config_frame, text="Join Session", variable=self.mode, value="connect", **radio_style).grid(row=0, column=1, padx=5)

        input_frame = tk.Frame(config_frame, bg=self.colors["header"])
        input_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=10)

        self.ip_entry = self.create_styled_entry(input_frame, "127.0.0.1", 15)
        self.ip_entry.pack(side=tk.LEFT, padx=5)

        self.port_entry = self.create_styled_entry(input_frame, "5000", 6)
        self.port_entry.pack(side=tk.LEFT, padx=5)

        self.name_entry = self.create_styled_entry(input_frame, "user", 10)
        self.name_entry.pack(side=tk.LEFT, padx=5)

        btn_frame = tk.Frame(config_frame, bg=self.colors["header"])
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="ew")

        tk.Button(btn_frame, text="Initialize", command=self.start_connection, bg=self.colors["accent"], fg="black", font=("Inter", 9, "bold"), relief=tk.FLAT, padx=20).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tk.Button(btn_frame, text="Terminate", command=self.disconnect, bg=self.colors["danger"], fg="white", font=("Inter", 9, "bold"), relief=tk.FLAT, padx=20).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        # Chat Display
        self.chat_area = scrolledtext.ScrolledText(
            self.root,
            wrap=tk.WORD,
            bg=self.colors["bg"],
            fg=self.colors["text"],
            font=("Inter", 11),
            padx=20,
            pady=20,
            borderwidth=0,
            highlightthickness=0
        )
        self.chat_area.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.chat_area.config(state=tk.DISABLED)

        self.chat_area.tag_configure("right", justify='right', lmargin1=100)
        self.chat_area.tag_configure("left", justify='left', rmargin=100)
        self.chat_area.tag_configure("center", justify='center')
        self.chat_area.tag_configure("sent_text", foreground=self.colors["accent"])
        self.chat_area.tag_configure("received_text", foreground="#ffffff")
        self.chat_area.tag_configure("sys_text", foreground=self.colors["system"], font=("Inter", 9, "italic"))

        # Input Section
        input_container = tk.Frame(self.root, bg=self.colors["bg"], pady=15, padx=15)
        input_container.pack(fill=tk.X)

        tk.Button(input_container, text="📎", command=self.send_file, bg=self.colors["header"], fg=self.colors["accent"], font=("Inter", 16), relief=tk.FLAT, bd=0).pack(side=tk.LEFT, padx=5)

        self.msg_entry = tk.Entry(
            input_container,
            bg=self.colors["header"],
            fg="white",
            insertbackground="white",
            font=("Inter", 12),
            relief=tk.FLAT,
            borderwidth=10
        )
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.msg_entry.bind("<Return>", lambda event: self.send_message())

        tk.Button(input_container, text="➤", command=self.send_message, bg=self.colors["accent"], fg="black", font=("Inter", 16, "bold"), relief=tk.FLAT, bd=0, width=3).pack(side=tk.LEFT, padx=5)

    def create_styled_entry(self, parent, default_text, width):
        e = tk.Entry(parent, width=width, bg=self.colors["bg"], fg="white", insertbackground="white", relief=tk.FLAT, borderwidth=5, font=("Inter", 10), justify='center')
        e.insert(0, default_text)
        return e

    # --- FUNCTIONALITY (Merged from App 2) ---

    def start_connection(self):
        name = self.name_entry.get()
        port = int(self.port_entry.get())
        mode = self.mode.get()
        ip = self.ip_entry.get()

        cert_path = f"certs/{name}.crt"
        key_path = f"certs/{name}.key"
        root_cert_path = "certs/rootCA.crt"

        self.peer = SecurePeer(name, cert_path, key_path, root_cert_path)
        threading.Thread(target=self.connect_thread, args=(mode, ip, port), daemon=True).start()

    def connect_thread(self, mode, ip, port):
        try:
            if mode == "listen":
                self.peer.listen(port)
            else:
                self.peer.connect(ip, port)

            # Functional requirement from App 2: Revocation Check
            if hasattr(self.peer, 'is_revoked') and self.peer.is_revoked():
                self.root.after(0, lambda: self.status_label.config(text="● ACCESS DENIED: REVOKED", fg=self.colors["danger"]))
                self.disconnect()
                return

            if not self.peer.secure_session:
                raise Exception("Handshake failed.")

            self.connected = True
            self.root.after(0, lambda: self.status_label.config(text="● Secure Connection Active", fg=self.colors["success"]))
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Connection Error", msg))

    def disconnect(self):
        if self.peer and self.peer.sock:
            try:
                self.peer.sock.shutdown(socket.SHUT_RDWR)
                self.peer.sock.close()
            except:
                pass
        self.connected = False
        self.peer = None
        self.status_label.config(text="● Offline", fg=self.colors["danger"])
        self.display_message("System", "Session terminated.", "center")

    def receive_messages(self):
        while self.connected:
            try:
                data = self.peer.recv_framed()
                if not data: break
                decrypted = self.peer.secure_session.decrypt(data)
                
                try:
                    message_obj = json.loads(decrypted)
                    if isinstance(message_obj, dict) and message_obj.get("type") == "file":
                        filename = message_obj["filename"]
                        file_bytes = base64.b64decode(message_obj["data"])
                        save_path = "received_" + filename
                        with open(save_path, "wb") as f:
                            f.write(file_bytes)
                        self.root.after(0, lambda: self.display_message("System", f"📎 Received: {save_path}", "left"))
                        continue
                except:
                    pass
                
                self.root.after(0, lambda msg=decrypted: self.display_chat_bubble("Peer", msg, "left"))
            except:
                break
        self.root.after(0, self.disconnect)

    def send_message(self):
        message = self.msg_entry.get()
        if not message or not self.connected: return
        try:
            encrypted = self.peer.secure_session.encrypt(message)
            self.peer.send_framed(encrypted)
            self.display_chat_bubble("You", message, "right")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def send_file(self):
        if not self.connected:
            messagebox.showerror("Error", "Connect first!")
            return
        file_path = filedialog.askopenfilename()
        if not file_path: return
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
            self.display_chat_bubble("You", f"📎 {payload['filename']}", "right")
        except Exception as e:
            messagebox.showerror("File Error", str(e))

    def display_chat_bubble(self, sender, message, side):
        self.chat_area.config(state=tk.NORMAL)
        alignment = side
        color_tag = "sent_text" if side == "right" else "received_text"
        content = f"\n{sender}\n{message}\n"
        self.chat_area.insert(tk.END, content, (alignment, color_tag))
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.see(tk.END)

    def display_message(self, sender, message, side):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"\n— {message} —\n", ("center", "sys_text"))
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()