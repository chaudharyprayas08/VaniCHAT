🖥️ LAPTOP 1 — ROOT CA SETUP (Do This Once)
✅ Step 1 — Create Folder Structure

On Laptop 1:

root_server/
│
├── certs/
├── generate_root.py
├── sign_request.py

Put your earlier generate_root.py inside this folder.

✅ Step 2 — Generate Root CA

Open terminal inside root_server/

Run:

python generate_root.py

It will create:

certs/rootCA.key
certs/rootCA.crt

📌 IMPORTANT:

Keep rootCA.key secret.

Never send rootCA.key to anyone.

Only rootCA.crt can be shared.

✅ Step 3 — Send rootCA.crt to Laptop 2

Email:

certs/rootCA.crt

to Laptop 2.

Now Laptop 2 trusts this Root CA.

Root CA setup is finished.

💻 LAPTOP 2 — USER SIDE
✅ Step 4 — Create Folder Structure

On Laptop 2:

user_client/
│
├── certs/
├── generate_user.py
├── verify_certificate.py

Place:

generate_user.py

verify_certificate.py

rootCA.crt (received from Laptop 1)

Inside certs/

✅ Step 5 — Generate User Key + CSR

Open terminal inside user_client/

Run:

python generate_user.py

This creates:

certs/user.key
certs/user.csr

It will also print:

Nonce: xxxxxxxxxxxxx

Keep note of that nonce (for understanding).

✅ Step 6 — Email CSR to Root CA

Send this file to Laptop 1:

certs/user.csr
🖥️ BACK TO LAPTOP 1 — CA ISSUANCE
✅ Step 7 — Place CSR in root_server Folder

Copy user.csr into:

root_server/

Rename to:

peerA.csr
✅ Step 8 — Run Certificate Signing

Inside root_server/ run:

python sign_request.py

This generates:

peerA.crt
response.sig

It also prints:

Fingerprint: xxxxxxxxxxxxx

📌 IMPORTANT:
Note this fingerprint.

✅ Step 9 — Email Back to Laptop 2

Send:

peerA.crt
response.sig
rootCA.crt
💻 LAPTOP 2 — FINAL VERIFICATION
✅ Step 10 — Place Received Files

Put these inside:

user_client/certs/

Rename:

peerA.crt → user.crt

Place:

response.sig

inside user_client/ folder.

✅ Step 11 — Run Verification

Inside user_client/ run:

python verify_certificate.py

You should see:

CA Signature verified.
Certificate chain verified.
Nonce inside certificate: xxxxx
Certificate Fingerprint: xxxxx
🔍 Step 12 — Manual Fingerprint Comparison

Now compare:

Fingerprint printed on Laptop 1

Fingerprint printed on Laptop 2

They must match exactly.

If they match:

✔ Certificate not tampered
✔ Email not modified
✔ CA signature valid
✔ Nonce preserved
✔ Trust established

🎯 What Just Happened

You implemented:

Manual PKI

Certificate issuance

Nonce replay protection

Digital signature verification

Fingerprint-based integrity check

Out-of-band verification

Without TLS.

This is strong academic work.

⚠️ Common Errors

If you get:

"Invalid CSR"

CSR was modified.

"Signature verification failed"

File corrupted or wrong rootCA.crt.

Nonce mismatch

Wrong CSR was signed.

🧠 After This

Now both laptops have:

Root CA certificate

User certificate

User private key

Now you are ready for:

Phase 2 → Peer-to-peer mutual authentication
Phase 3 → Diffie-Hellman key exchange
Phase 4 → AES encrypted chat