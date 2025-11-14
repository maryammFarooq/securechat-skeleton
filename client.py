# client.py

import socket
import json
import getpass # For securely typing passwords

# Import our helper module
import security_utils as sec

HOST = 'localhost'
PORT = 65432

def send_secure_command(sock, key, command_data):
    """Encrypts, sends a command, and returns the decrypted response."""
    # Send request
    request_json = json.dumps(command_data).encode('utf-8')
    encrypted_request = sec.encrypt_aes_cbc(key, request_json)
    sock.sendall(encrypted_request)

    # Get response
    encrypted_response = sock.recv(4096)
    if not encrypted_response:
        raise ConnectionError("Server disconnected.")

    decrypted_response = sec.decrypt_aes_cbc(key, encrypted_response)
    if not decrypted_response:
        raise Exception("Failed to decrypt server response.")

    return json.loads(decrypted_response.decode('utf-8'))

def main():
    """Main client function."""

    # Use a context manager for the socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print(f"Connected to server at {HOST}:{PORT}")

            # --- 1. Load Client Credentials ---
            print("Loading client credentials...")
            client_cert = sec.load_cert("client")
            client_key = sec.load_private_key("client")
            ca_cert = sec.load_ca_cert()

            # --- 2. Control Plane: Certificate Exchange (Req 1.1, 2.1) ---

            # Receive server's certificate
            print("Waiting for server certificate...")
            server_cert_bytes = s.recv(4096)
            if not server_cert_bytes:
                raise ConnectionError("Server disconnected during handshake.")

            server_cert = x509.load_pem_x509_certificate(server_cert_bytes, default_backend())

            # --- 3. Control Plane: Mutual Verification (Req 2.1) ---
            # Client MUST verify the server's cert
            if not sec.verify_peer_cert(server_cert, ca_cert, "localhost"):
                raise Exception("Server certificate verification FAILED.")

            print("Server certificate verified.")

            # Client sends its certificate
            print("Sending client certificate...")
            s.sendall(client_cert.public_bytes(serialization.Encoding.PEM))

            # --- 4. Control Plane: Temporary DH Exchange (Req 2.2) ---
            print("Starting temporary DH key exchange...")

            # Receive server's public DH key
            server_dh_public_bytes = s.recv(4096)
            if not server_dh_public_bytes:
                raise ConnectionError("Server disconnected during DH exchange.")

            # Generate client's DH keys
            client_dh_private, client_dh_public_bytes = sec.dh_generate_keys()

            # Send client's public DH key
            s.sendall(client_dh_public_bytes)

            # Derive temporary shared key
            temp_shared_secret = sec.dh_derive_shared_secret(client_dh_private, server_dh_public_bytes)
            temp_aes_key = sec.derive_key_from_dh_secret(temp_shared_secret)
            print("Temporary AES key established.")

            # --- 5. Control Plane: Secure Login/Register (Req 2.2) ---

            while True:
                print("\n--- Secure Portal ---")
                action = input("Type 'register' or 'login': ").strip().lower()

                if action == 'register':
                    email = input("Email: ")
                    username = input("Username: ")
                    password = getpass.getpass("Password: ")

                    # Client generates salt and hashes password
                    salt = sec.generate_salt()
                    pwd_hash = sec.hash_password(password, salt)

                    command = {
                        "type": "register",
                        "email": email,
                        "username": username,
                        "salt_hex": salt.hex(),
                        "pwd_hash": pwd_hash
                    }

                    response = send_secure_command(s, temp_aes_key, command)
                    print(f"Server: {response['message']}")

                elif action == 'login':
                    email = input("Email: ")
                    password = getpass.getpass("Password: ")

                    # 1. Request salt from server
                    salt_request = {"type": "login_request", "email": email}
                    response = send_secure_command(s, temp_aes_key, salt_request)

                    if response['status'] != 'ok' or response['salt_hex'] is None:
                        print("Server: Invalid email or password.")
                        continue

                    salt = bytes.fromhex(response['salt_hex'])

                    # 2. Hash password with received salt
                    pwd_hash = sec.hash_password(password, salt)

                    # 3. Send actual login command
                    login_command = {
                        "type": "login",
                        "email": email,
                        "pwd_hash": pwd_hash
                    }

                    response = send_secure_command(s, temp_aes_key, login_command)
                    print(f"Server: {response['message']}")

                    if response['status'] == 'ok':
                        print("Login successful!")
                        break # Exit login loop

                else:
                    print("Invalid command.")

            # --- 6. Session Key Establishment (Req 2.3) ---
            # TODO in Step 10
            print("Login complete. (Session key exchange not yet implemented)")


            # --- 7. Data Plane (Req 2.4) ---
            # TODO in Step 11
            print("Chat loop not yet implemented. Closing connection.")


        except Exception as e:
            print(f"\nERROR: {e}")
            traceback.print_exc()
        finally:
            print("Disconnected from server.")
            s.close()

if __name__ == "__main__":
    main()
