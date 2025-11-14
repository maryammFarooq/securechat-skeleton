# server.py

import socket
import json
import traceback
import mysql.connector

# Import our helper modules
import security_utils as sec
from config import DB_CONFIG

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
    session_key = None # This will be set in Step 10

    try:
        # --- 1. Load Server Credentials ---
        print("Loading server credentials...")
        server_cert = sec.load_cert("server")
        server_key = sec.load_private_key("server")
        ca_cert = sec.load_ca_cert()

        # --- 2. Control Plane: Certificate Exchange (Req 1.1, 2.1) ---

        # Server sends its certificate first
        print("Sending server certificate...")
        conn.sendall(server_cert.public_bytes(serialization.Encoding.PEM))

        # Server receives client's certificate
        print("Waiting for client certificate...")
        client_cert_bytes = conn.recv(4096) # Assume cert is < 4KB
        if not client_cert_bytes:
            raise ConnectionError("Client disconnected during handshake.")

        client_cert = x509.load_pem_x509_certificate(client_cert_bytes, default_backend())

        # --- 3. Control Plane: Mutual Verification (Req 2.1) ---
        if not sec.verify_peer_cert(client_cert, ca_cert, "client.user"):
            raise Exception("Client certificate verification FAILED.")

        print("Client certificate verified.")

        # --- 4. Control Plane: Temporary DH Exchange (Req 2.2) ---
        print("Starting temporary DH key exchange...")

        # Generate server's DH keys
        server_dh_private, server_dh_public_bytes = sec.dh_generate_keys()

        # Send server's public DH key
        conn.sendall(server_dh_public_bytes)

        # Receive client's public DH key
        client_dh_public_bytes = conn.recv(4096)
        if not client_dh_public_bytes:
            raise ConnectionError("Client disconnected during DH exchange.")

        # Derive temporary shared key
        temp_shared_secret = sec.dh_derive_shared_secret(server_dh_private, client_dh_public_bytes)
        temp_aes_key = sec.derive_key_from_dh_secret(temp_shared_secret)
        print("Temporary AES key established.")

        # --- 5. Control Plane: Secure Login/Register (Req 2.2) ---
        print("Waiting for secure login/register command...")

        while True:
            encrypted_request = conn.recv(4096)
            if not encrypted_request:
                raise ConnectionError("Client disconnected.")

            # Decrypt the request
            request_json = sec.decrypt_aes_cbc(temp_aes_key, encrypted_request)
            if not request_json:
                print("Failed to decrypt request. Terminating.")
                return

            request_data = json.loads(request_json.decode('utf-8'))
            print(f"Received command: {request_data['type']}")

            response_data = {}

            if request_data['type'] == 'register':
                response_data = handle_registration(request_data)
            elif request_data['type'] == 'login_request':
                response_data = handle_login_request(request_data)
            elif request_data['type'] == 'login':
                response_data = handle_login(request_data)

                # Encrypt and send the response
                response_json = json.dumps(response_data).encode('utf-8')
                encrypted_response = sec.encrypt_aes_cbc(temp_aes_key, response_json)
                conn.sendall(encrypted_response)

                if response_data['status'] == 'ok':
                    print("Login successful. Proceeding to session key exchange...")
                    break # Exit the login loop
            else:
                response_data = {"status": "error", "message": "Unknown command"}

            if request_data['type'] != 'login':
                # Encrypt and send the response
                response_json = json.dumps(response_data).encode('utf-8')
                encrypted_response = sec.encrypt_aes_cbc(temp_aes_key, response_json)
                conn.sendall(encrypted_response)

        # --- 6. Session Key Establishment (Req 2.3) ---
        # TODO in Step 10
        print("Login complete. (Session key exchange not yet implemented)")


        # --- 7. Data Plane (Req 2.4) ---
        # TODO in Step 11
        print("Chat loop not yet implemented.")


    except Exception as e:
        print(f"\nERROR handling client {addr}: {e}")
        traceback.print_exc()
    finally:
        print(f"[-] Closing connection from {addr}")
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
