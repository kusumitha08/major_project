# 🔐 Cross-Blockchain Passport Authentication

> Privacy-Preserving Cross-Blockchain Framework for Secure Passport Authentication using Aadhaar Identity Verification

[![Python](https://img.shields.io/badge/Python-3.9-blue.svg)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.19-orange.svg)](https://soliditylang.org)
[![Ethereum](https://img.shields.io/badge/Ethereum-Ganache-purple.svg)](https://trufflesuite.com/ganache)
[![Flask](https://img.shields.io/badge/Flask-2.x-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Proposed Solution](#proposed-solution)
- [System Architecture](#system-architecture)
- [Algorithms Used](#algorithms-used)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [API Endpoints](#api-endpoints)

---

## 📌 Overview

This project implements a **Privacy-Preserving Cross-Blockchain Framework** for secure passport authentication using Aadhaar identity verification. The system uses two independent Ethereum smart contracts deployed on Ganache blockchain — one representing the Aadhaar Blockchain and one representing the Passport Blockchain — connected through a secure Flask middleware layer.

The system verifies citizen identity using **SHA-256 hashing** and **ECDSA digital signatures** without exposing any raw personal data across blockchain boundaries.

---

## ❗ Problem Statement

Traditional passport authentication systems suffer from:

- Centralized databases vulnerable to data breaches
- Identity theft and unauthorized access
- Single points of failure
- No integration with Aadhaar infrastructure
- Privacy concerns when sharing identity data

---

## ✅ Proposed Solution

A privacy-preserving cross-blockchain authentication framework that:

- Uses **two independent blockchains** — Aadhaar and Passport
- Stores only **SHA-256 hashed identity** — never raw personal data
- Uses **ECDSA digital signatures** for cross-chain trust
- Transfers only **cryptographic proofs** through middleware
- Eliminates relay bridges reducing attack surface
- Provides immutable audit trail of all transactions

### Request Replay Protection

Each identity verification now receives a cryptographically random, single-use nonce from the middleware after the existing name and PIN checks succeed. The Aadhaar authority signs a SHA-256 hash of a domain-separated message containing the identity hash, request ID, and nonce. The middleware verifies that signature and consumes the request before returning success. Reused, expired, mismatched, or tampered challenges are rejected.

Nonce state is intentionally kept in the middleware because it protects the short-lived verification exchange and does not require changing or redeploying either existing registry contract. No raw Aadhaar data or private key material is added to blockchain records or API responses.

---

## 🏗️ System Architecture
 <img width="2962" height="2893" alt="archetecture1" src="https://github.com/user-attachments/assets/e941a527-7bf4-4eb9-9d59-25e8ba7a7872" />

### Three Main Components

| Component | Technology | Purpose |
|---|---|---|
| Aadhaar Blockchain | AadhaarRegistry.sol on Ganache | Stores hashed identity records |
| Passport Blockchain | PassportRegistry.sol on Ganache | Records passport applications |
| Middleware Layer | Flask REST API + web3.py | Connects both blockchains |

---

## 🔐 Algorithms Used

### Algorithm 1 — SHA-256 Based Identity Hashing
Input  : Name + DOB + AadhaarID
Process: SHA-256 cryptographic hash function
Output : 256-bit identity hash H

Properties:
- One-way function — cannot reverse hash
- Deterministic — same input always gives same output
- Avalanche effect — one character change changes entire hash
- Collision resistant — no two inputs produce same hash

### Algorithm 2 — ECDSA Based Cross-Blockchain Verification

**Signing (Aadhaar Side):**
Input  : Hash H, Private Key PrivA
- Step 1 : Generate random k
- Step 2 : R = k · G (elliptic curve point)
- Step 3 : r = x-coordinate of R
- Step 4 : s = k⁻¹(H + r · PrivA) mod n
- Output : Signature (r, s)

**Verification (Passport Side):**
Input  : Hash H, Signature (r,s), Public Key PubA
- Step 1 : w  = s⁻¹ mod n
- Step 2 : u1 = H · w mod n
- Step 3 : u2 = r · w mod n
- Step 4 : P  = u1·G + u2·PubA
- Check  : x-coordinate of P = r → ACCEPT
else → REJECT

---

## 🛠️ Technology Stack

| Technology | Version | Purpose |
|---|---|---|
| Python | 3.9 | Primary backend language |
| SHA-256 (hashlib) | Built-in | Identity hashing |
| ECDSA (ecdsa library) | Latest | Digital signatures |
| Solidity | 0.8.19 | Smart contract language |
| Ganache | 7.9.2 | Local Ethereum blockchain |
| Truffle | 5.11.5 | Contract deployment framework |
| web3.py | Latest | Blockchain interaction |
| Flask | Latest | Middleware REST API |
| Flask-CORS | Latest | Cross-origin support |
| HTML/CSS/JavaScript | — | Frontend interface |
| Node.js | 22.x | Runtime for Truffle and Ganache |

---

## 📁 Project Structure

```
cross-blockchain-passport/
|
|-- contracts/
|   |-- AadhaarRegistry.sol        (Aadhaar Blockchain smart contract)
|   |-- PassportRegistry.sol       (Passport Blockchain smart contract)
|
|-- migrations/
|   |-- 2_deploy_contracts.js      (Contract deployment script)
|
|-- crypto_core/
|   |-- crypto_utils.py            (SHA-256 + ECDSA implementation)
|   |-- keys.py                    (Key management system)
|   |-- contract_addresses.json    (Deployed contract addresses)
|
|-- middleware/
|   |-- app.py                     (Flask REST API middleware)
|
|-- frontend/
|   |-- index.html                 (Web interface)
|
|-- start.py                       (Auto startup script)
|-- truffle-config.js              (Truffle configuration)
|-- README.md                      (Project documentation)
```
---

## ⚙️ Installation

### Prerequisites

Make sure you have installed:
- Python 3.9+
- Node.js 18+
- VS Code

### Step 1 — Clone Repository

```bash
git clone https://github.com/kusumitha08/cross-blockchain-passport.git
cd cross-blockchain-passport
```

### Step 2 — Install Python Dependencies

```bash
pip install web3 flask ecdsa flask-cors requests
```

### Step 3 — Install Node Dependencies

```bash
npm install -g ganache
npm install -g truffle
```

### Step 4 — Verify Installation

```bash
ganache --version
truffle version
python -c "import web3, flask, ecdsa; print('All good!')"
```

### Account Access

Applicants create an account with their name, email, and password from **Login**. Their password is stored as a salted hash in the local, ignored file `middleware/accounts.json`; it is never stored as readable text. Returning applicants sign in with email and password.

Developer sign-in accepts only these four USNs: `1si23is025`, `1si23is038`, `1si23is119`, and `1si23is120`. All four use the shared development password `12345678`. The backend stores only its password hash and rejects all other USNs. This shared password is for local development only; replace it with individual credentials before any real deployment. Protected services are checked by the middleware, so changing browser storage cannot grant a role.

---

## ▶️ How to Run

### Step 1 — Start Ganache (Terminal 1)

```bash
ganache --database.dbPath ./.ganache --port 8545 --accounts 10 --deterministic
```

The `.ganache` directory preserves registrations and application decisions between Ganache restarts. `start.py` reuses saved deployed contracts and never force-resets them, so restarting the web application does not clear history. If you previously ran Ganache without a database path, its in-memory records cannot automatically be transferred into `.ganache`; an earlier forced reset also permanently removed any history that was already cleared.

Wait until you see:
✅ Connected to Ganache blockchain!
Running on http://127.0.0.1:5000

### Step 3 — Run Startup Script (Terminal 3)

```bash
python start.py
```

This automatically:
- Deploys both smart contracts to Ganache
- Updates contract addresses
- Starts the frontend after Flask is restarted

Applicants create an account from the portal, then sign in to register identities and submit applications. The startup script no longer inserts anonymous sample citizens.

### PIN Reset Email

PIN-reset OTPs are sent to the email address on the applicant account used when registering the Aadhaar record. Configure SMTP credentials in the same terminal before starting the middleware. For Gmail, enable 2-Step Verification and create an App Password; use that App Password here, not your Google account password:

```powershell
$env:SMTP_USERNAME = "your-address@gmail.com"
$env:SMTP_PASSWORD = "your-16-character-app-password"
$env:SMTP_FROM_EMAIL = "your-address@gmail.com"
```

The default SMTP server is `smtp.gmail.com` on port `587`. `SMTP_HOST` and `SMTP_PORT` can be set to use another SMTP provider. Existing Aadhaar PIN records without an `email` field must be linked to the correct applicant account email before email-based PIN reset can be used.

### Step 4 — Restart Flask After start.py Asks

Stop Flask with Ctrl+C and run again:
```bash
python app.py
```

Then return to Terminal 3 and press Enter so `start.py` can finish and launch the frontend. Applicants register their identities after creating an account in the portal.

### Step 5 — Open Frontend

After setup finishes, `start.py` starts the frontend server and prints its URL (normally `http://127.0.0.1:5500/`). Open that URL in your browser. You do not need to start Live Server separately.

---

## 🌐 API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Check system status |
| GET | `/stats` | View public aggregate counts |
| POST | `/auth/applicant/signup` | Create an applicant account |
| POST | `/auth/applicant/login` | Sign in as an applicant |
| POST | `/auth/developer/login` | Sign in with an authorized, provisioned developer USN |
| GET | `/auth/session` | Check the current sign-in |
| POST | `/auth/logout` | End the current sign-in |
| POST | `/aadhaar/register` | Register citizen on Aadhaar Blockchain |
| GET | `/aadhaar/citizens` | View all registered citizens |
| GET | `/aadhaar/proof/<aadhaar_id>` | Get identity proof from blockchain |
| POST | `/passport/apply` | Apply for passport |
| GET | `/passport/progress/<aadhaar_id>` | View an applicant's matching progress |
| GET | `/passport/applications` | View all passport applications |
| GET | `/passport/validate` | Validate blockchain stats |

### Example API Calls

**Register Citizen:**
```bash
POST http://localhost:5000/aadhaar/register
{
    "name"      : "Rajesh Kumar",
    "dob"       : "15-06-1985",
    "aadhaar_id": "1111-2222-3333"
}
```

**Apply for Passport:**
```bash
POST http://localhost:5000/passport/apply
{
    "name"      : "Rajesh Kumar",
    "aadhaar_id": "1111-2222-3333"
}
```

**Get Identity Proof:**
```bash
GET http://localhost:5000/aadhaar/proof/1111-2222-3333
```

---

## 🔒 Security Properties

| Property | Implementation |
|---|---|
| **Privacy** | Raw personal data never leaves Aadhaar Blockchain |
| **Integrity** | SHA-256 ensures any tampering changes the hash |
| **Authentication** | ECDSA signature proves identity from Aadhaar authority |
| **Immutability** | All records permanently stored on blockchain |
| **Non-repudiation** | Aadhaar authority cannot deny signing identity |
| **Cross-chain trust** | Passport chain verifies locally using public key |

---

## 🔄 Cross-Blockchain Verification Flow
- Step 1 → Citizen submits passport application
- Step 2 → Middleware contacts Aadhaar Blockchain
- Step 3 → Aadhaar Blockchain returns Hash + Signature only
- Step 4 → Middleware passes proof to Passport Blockchain
- Step 5 → Passport Blockchain verifies ECDSA signature
- Step 6 → APPROVED or REJECTED recorded on Passport Blockchain

---

## 📊 Sample Test Data

| Name | DOB | Aadhaar ID |
|---|---|---|
| Rajesh Kumar | 15-06-1985 | 1111-2222-3333 |
| Priya Sharma | 22-03-1990 | 2222-3333-4444 |
| Arun Mehta | 08-11-1978 | 3333-4444-5555 |
| Divya Nair | 30-07-1995 | 4444-5555-6666 |

---

## 🚀 Future Work

- Zero Knowledge Proofs for enhanced privacy
- Real Aadhaar UIDAI API integration
- Multi-node permissioned blockchain deployment
- Performance benchmarking against existing systems
- Biometric verification support
- Hardware Security Module for key management

---

## 📚 References

1. Cheng et al. — Secure Cross-Blockchain Interaction Framework — IEEE Access 2024
2. Gupta et al. — Blockchain-Based Digital Passport Management — SMARTCOMP 2023
3. Singh and Patel — Blockchain-Based Identity Management — Future Generation Computer Systems 2024
4. Verma and Rao — Privacy-Preserving Blockchain Authentication Using ZKP — IEEE Access 2024
5. UIDAI — Aadhaar Authentication Framework — Government of India 2022

---
