# Secure File Transfer with Hybrid Encryption & ML Threat Detection

A high-assurance, zero-trust web application combining **Hybrid Cryptography (AES-256-GCM + RSA-4096)** with **Machine Learning-driven Anomaly Detection (Isolation Forest)** for secure end-to-end file sharing and tamper verification.

---

## 🔒 What is Hybrid Encryption?

Pure symmetric encryption (such as AES) is extremely fast for large files, but transferring the secret key securely across untrusted networks is difficult. Pure asymmetric encryption (such as RSA) solves key distribution with public/private key pairs, but is computationally slow and mathematically restricted to small data blocks.

**Hybrid Encryption delivers the best of both worlds:**
1. **Bulk Data Protection**: The uploaded payload is encrypted at hardware speed using a freshly generated, single-use **AES-256-GCM** key. This also produces an authentication tag guaranteeing message integrity.
2. **Key Encapsulation**: The ephemeral 256-bit AES key is encrypted using the recipient's **RSA-4096-OAEP** public key.
3. **Decryption**: Only the recipient possessing the private RSA key can unwrap the AES key and decrypt the payload.
4. **Integrity Validation**: SHA-256 digests and AES-GCM tags guarantee zero alteration or tampering.

```
[Plaintext File] ──► [AES-256-GCM Encryption] ──► [Encrypted Payload] ──┐
                            ▲                                            │
                     [Random AES Key]                                    ├─► [Secure Transfer Package]
                            │                                            │
                    [RSA-4096 Public Key]                                │
                            ▼                                            │
               [Encrypted Key via RSA-OAEP] ─────────────────────────────┘
```

---

## ✨ Features

- 🔑 **RSA-4096 Vault Keypair Generation**: Generates military-grade asymmetric keypairs per user identity with in-memory private key vaulting.
- 🛡️ **Machine Learning Threat Sentinel**: Scans files prior to encryption using Scikit-Learn's `IsolationForest` to detect suspicious patterns, high-entropy packed payloads, and file extension mismatches.
- ⚡ **Animated 5-Stage Encryption Pipeline**: Live UI feedback visualizing scanning, key generation, AES-GCM encryption, RSA-OAEP key wrapping, and secure package storage.
- ⛓️ **Blockchain Integrity Ledger**: Displays connected hash blocks (SHA-256 chained digests) with simulated immutability and animated verification pulses upon download.
- 📊 **Real-Time Security Dashboard**: Live metrics tracking Files Scanned, Threats Blocked, Safe Files, dynamic conic-gradient ML Confidence Gauge, and live event monitoring logs.
- 🎨 **Cybersecurity Dark Theme**: Terminal-inspired dark interface with glassmorphism, glowing neon accents (`#00ff88`, `#00d4ff`, `#ff3366`), and monospace technical telemetry.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.10+, Flask
- **Cryptography**: PyCryptodome (AES-256-GCM, RSA-4096, PKCS1_OAEP, SHA-256)
- **Machine Learning**: Scikit-Learn (`IsolationForest`), NumPy
- **Frontend**: Vanilla HTML5, CSS3 (Glassmorphism, CSS Grid, Conic Gradients), Vanilla JavaScript (ES6+ Fetch API)
- **Production Server**: Gunicorn

---

## 📸 Screenshots

### 1. Security Operations Dashboard & Key Generation
```
+-----------------------------------------------------------------------+
|  [SCREENSHOT PLACEHOLDER: Live Security Dashboard & Key Generation]   |
|  (Displays files scanned, threat counters, confidence gauge & Step 1) |
+-----------------------------------------------------------------------+
```
*(Add screenshot here: `docs/screenshots/dashboard.png`)*

### 2. Animated Hybrid Encryption Pipeline
```
+-----------------------------------------------------------------------+
|  [SCREENSHOT PLACEHOLDER: Step-by-Step Hybrid Encryption Pipeline]    |
|  (Displays ML scan check, AES-GCM lock, RSA wrapping & time taken)    |
+-----------------------------------------------------------------------+
```
*(Add screenshot here: `docs/screenshots/pipeline.png`)*

### 3. Blockchain Ledger & Architecture Flow
```
+-----------------------------------------------------------------------+
|  [SCREENSHOT PLACEHOLDER: Blockchain Integrity Ledger & Flow Diagram] |
|  (Displays chained blocks, verified status & Why Hybrid section)      |
+-----------------------------------------------------------------------+
```
*(Add screenshot here: `docs/screenshots/blockchain.png`)*

---

## 🚀 Installation & Local Setup

### Prerequisites
- Python 3.9 or higher
- `pip` package manager
- `git`

### Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/<your-repo-name>.git
   cd <your-repo-name>
   ```

2. **Create and activate a virtual environment (optional but recommended):**
   ```bash
   # On Windows:
   python -m venv venv
   .\venv\Scripts\activate

   # On macOS/Linux:
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the application:**
   ```bash
   python app.py
   ```

5. **Open in browser:**
   Navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 👥 Project Team

- **Lead Developer**: [Member Name 1] - *Full-Stack Development & Cryptography Architecture*
- **Security & ML Engineer**: [Member Name 2] - *Threat Detection Model & Security Engineering*
- **UI/UX Designer**: [Member Name 3] - *Frontend Styling & Interface Design*
