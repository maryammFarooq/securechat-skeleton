# Secure Chat System --- Client/Server (Information Security Assignment 2)

This project delivers a custom-built secure chat application running
entirely over plain TCP sockets. It is created for **FAST NUCES --
Information Security, Assignment 2 (Fall 2025)** and demonstrates how
multiple cryptographic mechanisms can be combined to build a secure
communication protocol without depending on TLS/SSL.

The application is implemented in Python and uses the following
cryptographic components:

-   **AES-128 encryption (CBC mode + PKCS#7 padding)**
-   **RSA-2048 signatures (PKCS#1 v1.5 with SHA-256)**
-   **Diffie--Hellman key exchange**
-   **SHA-256 hashing**
-   **X.509 certificates issued by a custom Certificate Authority**

The system achieves:

-   **Confidentiality** through AES-encrypted traffic
-   **Integrity** via SHA-256 digests
-   **Authenticity** with certificate-based verification
-   **Non-Repudiation** using session transcripts and signed receipts

------------------------------------------------------------------------

## 🔧 1. Environment Setup

These instructions apply to **Kali Linux / Debian-based systems**.

------------------------------------------------------------------------

### 1.1 Install Required Packages

``` bash
sudo apt update
sudo apt -y upgrade
sudo apt install -y git mariadb-server python3-venv
```

------------------------------------------------------------------------

### 1.2 Secure MariaDB

``` bash
sudo mariadb-secure-installation
```

Recommended settings:

-   Set root password
-   Remove anonymous users
-   Disable remote root login
-   Remove test DB
-   Reload privilege tables

------------------------------------------------------------------------

## ⚙️ 2. Project Configuration

### 2.1 Clone Repo and Create Virtual Environment

``` bash
git clone https://github.com/maryammFarooq/securechat-skeleton.git
cd securechat-skeleton
python3 -m venv venv
source venv/bin/activate
pip install cryptography mysql-connector-python
```

------------------------------------------------------------------------

### 2.2 Configure Database

Set the root password:

``` sql
ALTER USER 'root'@'localhost' IDENTIFIED BY 'YOUR_PASSWORD_HERE';
FLUSH PRIVILEGES;
```

Create database + users table:

``` sql
CREATE DATABASE secure_chat;
USE secure_chat;

CREATE TABLE users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    PRIMARY KEY (email)
);
```

------------------------------------------------------------------------

### 2.3 Create config.py

Create a new file named **config.py**:

``` python
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'YOUR_PASSWORD_HERE',
    'database': 'secure_chat'
}
```

Add this file to `.gitignore` so credentials are not pushed to GitHub.

------------------------------------------------------------------------

## 🔑 3. Certificates & Key Generation

Run the provided scripts:

``` bash
python3 scripts/gen_ca.py
python3 scripts/gen_cert.py server localhost
python3 scripts/gen_cert.py client client.user
python3 scripts/gen_dh_params.py
```

This generates:

-   Root CA certificate
-   Server certificate
-   Client certificate
-   Diffie--Hellman parameters

------------------------------------------------------------------------

## ▶️ 4. Running the Secure Chat System

Start the server:

``` bash
python3 server.py
```

Start the client:

``` bash
python3 client.py
```

The system supports registration, login, key exchange, encrypted
messaging, replay protection, and session closure with signed receipts.

------------------------------------------------------------------------

## 💬 5. Features Implemented

-   Mutual certificate verification
-   Secure registration & login (salted SHA-256)
-   Temporary DH exchange for encrypted credentials
-   Session DH exchange for final AES-128 key
-   RSA-signed chat messages
-   Replay protection via sequence numbers
-   Full transcript logging
-   Signed SessionReceipt for non-repudiation

------------------------------------------------------------------------

## 🧪 6. Offline Transcript Verification

``` bash
python3 verify_transcript.py client_receipt.json client_transcript.log
```

Expected output:

    Hash OK
    Signature VALID
    Transcript authentic and unchanged.

------------------------------------------------------------------------

## ✔️ End of README.md
