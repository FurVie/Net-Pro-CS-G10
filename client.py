import socket
import ssl
import os
import hashlib

HOST = 'localhost'
PORT = 12345

# Create an SSL context for client-side communication
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False  # Disable hostname verification (for testing)
context.verify_mode = ssl.CERT_NONE  # Disable certificate verification (for testing)

# Create a plain socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the socket with SSL
secure_socket = context.wrap_socket(sock, server_hostname=HOST)

def calculate_checksum(file_path):
    """Calculate SHA-256 checksum of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
        exit(1)  # Exit if file not found
    except Exception as e:
        print(f"Error calculating checksum: {e}")
        exit(1)

def send_file(file_path):
    """Send a file with checksum to the server."""
    checksum = calculate_checksum(file_path)
    try:
        with open(file_path, "rb") as f:
            # Send checksum first
            secure_socket.send(checksum.encode())  
            file_size = os.path.getsize(file_path)
            secure_socket.send(str(file_size).encode())  # Send file size
            
            # Send the file data in chunks
            while chunk := f.read(1024):
                secure_socket.send(chunk)

            print(f"File '{file_path}' sent with checksum {checksum}")
    except Exception as e:
        print(f"Error sending file: {e}")
        exit(1)

try:
    # Connect to the server
    secure_socket.connect((HOST, PORT))
    print("SSL/TLS connection established!")

    # Send a message
    secure_socket.send(b"Hello, server!")

    # Receive a response
    response = secure_socket.recv(1024)
    print("Server response:", response.decode())

    # Send a file
    file_path = "example.pdf"  # Replace with your actual file path
    send_file(file_path)
finally:
    # Close the connection
    secure_socket.close()
