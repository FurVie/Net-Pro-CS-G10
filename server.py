import socket
import ssl
import hashlib

HOST = 'localhost'
PORT = 12345

CERT = "C:/Users/minh/Downloads/vscode/network programming/cert.pem"
KEY = "C:/Users/minh/Downloads/vscode/network programming/key.pem"

# Set up the server to listen for incoming connections
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Binding the server to a specific host and port
server_socket.bind(('0.0.0.0', PORT))  # Listen on all IP addresses at port 12345
server_socket.listen(5)
print(f"Server listening on port {PORT}...")

# Wrapping the socket with SSL using create_default_context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=CERT, keyfile=KEY)

# Secure server socket
secure_socket = context.wrap_socket(server_socket, server_side=True)

def calculate_checksum(file_path):
    """Calculate SHA-256 checksum of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating checksum: {e}")
        return None

def receive_file(client_socket):
    """Receive a file and verify checksum."""
    try:
        # Receive checksum first
        checksum = client_socket.recv(64).decode()  # SHA-256 checksum length
        if not checksum:
            print("No checksum received.")
            return

        file_size = int(client_socket.recv(1024).decode())
        if not file_size:
            print("No file size received.")
            return

        file_name = "received_file"  # You can modify this to handle naming
        with open(file_name, "wb") as f:
            total_received = 0
            while total_received < file_size:
                chunk = client_socket.recv(1024)
                if not chunk:
                    break  # Break if client disconnects or sends no data
                total_received += len(chunk)
                f.write(chunk)

            print(f"File '{file_name}' received!")

        # Verify the file checksum
        received_checksum = calculate_checksum(file_name)
        if received_checksum == checksum:
            print("Checksum verified successfully!")
        else:
            print("Checksum mismatch! File may be corrupted.")

    except Exception as e:
        print(f"Error receiving file: {e}")

while True:
    # Accept incoming connections
    client_socket, addr = secure_socket.accept()
    print(f"Connection from {addr}")

    # Send a welcome message to the client
    client_socket.send(b"Welcome to the secure server!\n")

    # Receive and print client messages
    message = client_socket.recv(1024)
    print(f"Received message: {message.decode()}")

    # Receive and handle the file transfer
    receive_file(client_socket)

    # Close the connection
    client_socket.close()
