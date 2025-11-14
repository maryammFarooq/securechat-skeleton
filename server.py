# server.py

import socket
import json
import traceback
import mysql.connector
import threading
import datetime
from pathlib import Path

# Import our helper modules
import security_utils as sec
from config import DB_CONFIG
from cryptography.hazmat.primitives import serialization
from cryptography import x509  # <-- ADD THIS LINE
from cryptography.hazmat.backends import default_backend  # <-- ADD THIS LINE

HOST = 'localhost'
PORT = 65432

def get_db_connection():
    """Establishes a connection to the MariaDB database."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        print("Database connection successful.")
        return conn
    except mysql.connector.Error as err:
        print(f"DATABASE ERROR: {err}")
        return None

def handle_registration(data):
    """Handles 'register' command. (Req 2.2)"""
    email = data['email']
    username = data['username']
    # Note: password is sent as hash_hex
    pwd_hash = data['pwd_hash']
    # Salt is sent in bytes, needs to be stored
    salt = bytes.fromhex(data['salt_hex'])

    conn = get_db_connection()
    if not conn:
        return {"status": "error", "message": "Database connection failed."}

    try:
        cursor = conn.cursor()
        # Insert new user
        query = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (email, username, salt, pwd_hash))
        conn.commit()
        print(f"New user registered: {username}")
        return {"status": "ok", "message": "Registration successful."}
    except mysql.connector.Error as err:
        if err.errno == 1062: # Duplicate entry
            return {"status": "error", "message": "Email or username already exists."}
        return {"status": "error", "message": f"Database error: {err}"}
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def handle_login(data):
    """Handles 'login' command. (Req 2.2)"""
    email = data['email']
    client_pwd_hash = data['pwd_hash']

    conn = get_db_connection()
    if not conn:
        return {"status": "error", "message": "Database connection failed."}

    try:
        cursor = conn.cursor(dictionary=True)
        # Fetch user's salt and stored hash
        query = "SELECT salt, pwd_hash, username FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if not user:
            return {"status": "error", "message": "Invalid email or password."}

        # Re-compute hash using stored salt and compare
        stored_salt = user['salt']
        stored_hash = user['pwd_hash']

        # The client computed SHA256(stored_salt || password). We check it.
        if client_pwd_hash == stored_hash:
            print(f"User logged in: {user['username']}")
            # Send back the username, client will need it
            return {"status": "ok", "message": "Login successful.", "username": user['username']}
        else:
            return {"status": "error", "message": "Invalid email or password."}

    except mysql.connector.Error as err:
        return {"status": "error", "message": f"Database error: {err}"}
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def handle_login_request(data):
    """Handles 'login_request' to get salt."""
    email = data['email']
    conn = get_db_connection()
    if not conn:
        return {"status": "error", "message": "Database connection failed."}

    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT salt FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if user:
            # Return salt as hex
            return {"status": "ok", "salt_hex": user['salt'].hex()}
        else:
            # Still return "ok" but with no salt, to prevent email enumeration
            return {"status": "ok", "salt_hex": None}
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def handle_client(conn, addr):
    """
    Main function to handle a single client connection.
    """
    print(f"\n[+] New connection from {addr}")
    client_cert = None
    session_key = None
    server_key = None

    # Open transcript file
    transcript_path = Path(f"server_transcript_{addr[0]}_{addr[1]}.log")
    with transcript_path.open("a") as transcript_file:
        def log_message(msg):
            """Helper to log to file and console."""
            print(msg)
            transcript_file.write(f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} | {msg}\n")

        try:
            # --- 1. Load Server Credentials ---
            log_message("Loading server credentials...")
            server_cert = sec.load_cert("server")
            server_key = sec.load_private_key("server")
            ca_cert = sec.load_ca_cert()

            # --- 2. Control Plane: Certificate Exchange (Req 1.1, 2.1) ---
            log_message("Sending server certificate...")
            conn.sendall(server_cert.public_bytes(serialization.Encoding.PEM))

            log_message("Waiting for client certificate...")
            client_cert_bytes = conn.recv(4096)
            if not client_cert_bytes:
                raise ConnectionError("Client disconnected during handshake.")

            client_cert = x509.load_pem_x509_certificate(client_cert_bytes, default_backend())

            # --- 3. Control Plane: Mutual Verification (Req 2.1) ---
            if not sec.verify_peer_cert(client_cert, ca_cert, "client.user"):
                raise Exception("Client certificate verification FAILED.")

            log_message("Client certificate verified.")

            # --- 4. Control Plane: Temporary DH Exchange (Req 2.2) ---
            log_message("Starting temporary DH key exchange...")
            server_dh_private, server_dh_public_bytes = sec.dh_generate_keys()
            conn.sendall(server_dh_public_bytes)
            client_dh_public_bytes = conn.recv(4096)
            if not client_dh_public_bytes:
                raise ConnectionError("Client disconnected during DH exchange.")

            temp_shared_secret = sec.dh_derive_shared_secret(server_dh_private, client_dh_public_bytes)
            temp_aes_key = sec.derive_key_from_dh_secret(temp_shared_secret)
            log_message("Temporary AES key established.")

            # --- 5. Control Plane: Secure Login/Register (Req 2.2) ---
            log_message("Waiting for secure login/register command...")

            client_username = "" # Store this for the chat

            while True:
                encrypted_request = conn.recv(4096)
                if not encrypted_request:
                    raise ConnectionError("Client disconnected.")

                request_json = sec.decrypt_aes_cbc(temp_aes_key, encrypted_request)
                if not request_json:
                    log_message("Failed to decrypt request. Terminating.")
                    return

                request_data = json.loads(request_json.decode('utf-8'))
                log_message(f"Received command: {request_data['type']}")

                response_data = {}

                if request_data['type'] == 'register':
                    response_data = handle_registration(request_data)
                elif request_data['type'] == 'login_request':
                    response_data = handle_login_request(request_data)
                elif request_data['type'] == 'login':
                    response_data = handle_login(request_data)

                    response_json = json.dumps(response_data).encode('utf-8')
                    encrypted_response = sec.encrypt_aes_cbc(temp_aes_key, response_json)
                    conn.sendall(encrypted_response)

                    if response_data['status'] == 'ok':
                        log_message("Login successful. Proceeding to session key exchange...")
                        client_username = response_data.get('username', 'client') # Get username
                        break # Exit the login loop
                else:
                    response_data = {"status": "error", "message": "Unknown command"}

                if request_data['type'] != 'login':
                    response_json = json.dumps(response_data).encode('utf-8')
                    encrypted_response = sec.encrypt_aes_cbc(temp_aes_key, response_json)
                    conn.sendall(encrypted_response)

            # --- 6. Session Key Establishment (Req 2.3) ---
            log_message("Starting SESSION key exchange...")
            session_dh_private, session_dh_public_bytes = sec.dh_generate_keys()
            conn.sendall(session_dh_public_bytes)

            client_session_dh_public_bytes = conn.recv(4096)
            if not client_session_dh_public_bytes:
                raise ConnectionError("Client disconnected during session key exchange.")

            session_shared_secret = sec.dh_derive_shared_secret(session_dh_private, client_session_dh_public_bytes)
            session_key = sec.derive_key_from_dh_secret(session_shared_secret)
            log_message("✅ Secure session key established.")

            # --- 7. Data Plane (Req 2.4) ---
            log_message("Starting secure chat. Type 'logout' to exit.")

            # We need the client's public key to verify their messages
            client_public_key = client_cert.public_key()

            # Simple chat loop (no threads on server, just listen)
            seq_no = 0
            while True:
                encrypted_message = conn.recv(4096)
                if not encrypted_message:
                    log_message("Client disconnected.")
                    break

                # Decrypt with SESSION key
                message_json = sec.decrypt_aes_cbc(session_key, encrypted_message)
                if not message_json:
                    log_message("ERROR: Could not decrypt message. Ignoring.")
                    continue

                msg = json.loads(message_json.decode('utf-8'))

                if msg['type'] == 'logout':
                    log_message(f"Client {client_username} is logging out.")
                    break # Exit chat loop

                # Verify message (Req 2.4: Integrity, Authenticity, Replay)
                rcv_seq_no = msg['seqno']
                rcv_ts = msg['ts']
                rcv_ct_hex = msg['ct_hex']
                rcv_sig_hex = msg['sig_hex']

                # 1. Replay check
                if rcv_seq_no <= seq_no:
                    log_message(f"REPLAY DETECTED! Old seq={rcv_seq_no}, expected > {seq_no}. Ignoring.")
                    continue
                seq_no = rcv_seq_no

                # 2. Re-compute hash
                # The client signed SHA256(seqno || timestamp || ciphertext)
                ct_bytes = bytes.fromhex(rcv_ct_hex)
                data_to_verify = f"{rcv_seq_no}{rcv_ts}".encode('utf-8') + ct_bytes
                digest = sec.hash_sha256(data_to_verify)

                # 3. Verify signature
                sig_bytes = bytes.fromhex(rcv_sig_hex)
                if not sec.verify_signature(client_public_key, sig_bytes, digest):
                    log_message(f"INVALID SIGNATURE! Message from {client_username} tampered. Ignoring.")
                    continue

                # 4. Decrypt ciphertext (from chat message)
                plaintext = sec.decrypt_aes_cbc(session_key, ct_bytes)
                if not plaintext:
                    log_message("ERROR: Could not decrypt inner ciphertext. Ignoring.")
                    continue

                log_message(f"[{client_username}]: {plaintext.decode('utf-8')}")

                # (This is a simple echo server for the assignment)
                # TODO: A real server would have an admin type a reply.
                # For now, just log and wait for next message.

        except ConnectionResetError:
            log_message(f"Client {addr} reset the connection.")
        except Exception as e:
            log_message(f"\nERROR handling client {addr}: {e}")
            traceback.print_exc()
        finally:
            log_message(f"[-] Closing connection from {addr}")

            # --- 8. Non-Repudiation: Session Receipt (Req 2.5) ---
            transcript_file.flush() # Make sure all data is written

            # Hash the entire transcript
            transcript_data = Path(transcript_path).read_bytes()
            transcript_hash = sec.hash_sha256(transcript_data)

            # Sign the hash with the SERVER's key
            receipt_sig = sec.sign(server_key, transcript_hash)

            receipt = {
                "type": "SessionReceipt",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "server_cert": server_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                "client_cert": client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                "transcript_hash_hex": transcript_hash.hex(),
                "signature_hex": receipt_sig.hex()
            }

            receipt_path = Path(f"server_receipt_{addr[0]}_{addr[1]}.json")
            with receipt_path.open("w") as f:
                json.dump(receipt, f, indent=2)

            print(f"Session receipt saved to {receipt_path}")
            conn.close()

def main():
    """Main server loop."""
    # Ensure DB connection is possible
    conn = get_db_connection()
    if conn:
        conn.close()
        print("Server starting...")
    else:
        print("CRITICAL: Could not connect to database. Check config.py and MariaDB status.")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")

        try:
            while True:
                conn, addr = s.accept()
                # For this assignment, we'll handle one client at a time.
                # A real server would use threading.
                handle_client(conn, addr)
        except KeyboardInterrupt:
            print("\nServer shutting down.")
        finally:
            s.close()

if __name__ == "__main__":
    main()
