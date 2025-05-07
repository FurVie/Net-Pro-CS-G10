import socket
import ssl
import threading
import os
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QFileDialog, QMenu, QInputDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from utils import calculate_checksum

CERT_FILE = "C:/Users/phamh/projects/netpro2/cert.pem"
KEY_FILE = "C:/Users/phamh/projects/netpro2/key.pem"

HOST = "0.0.0.0"
PORT = 12345

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

clients = []


class ChatServerWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Secure Chat Server")
        self.setGeometry(100, 100, 700, 500)

        self.name, ok = QInputDialog.getText(self, "Enter Name", "Your name:")
        if not ok or not self.name.strip():
            self.name = "Server"

        self.chat_area = QTextEdit(self)
        self.chat_area.setReadOnly(True)
        self.chat_area.setStyleSheet("""
            background-color: #2e2e2e;
            font-size: 14px;
            color: #ffffff;
            padding: 8px;
        """)

        self.entry = QLineEdit(self)
        self.entry.setPlaceholderText("Type your message…")
        self.entry.returnPressed.connect(self.send_message)

        self.send_button = QPushButton("Send", self)
        self.send_button.clicked.connect(self.send_message)

        self.file_button = QPushButton("Send File", self)
        self.file_button.clicked.connect(self.browse_file)

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.entry)
        input_layout.addWidget(self.send_button)
        input_layout.addWidget(self.file_button)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.chat_area)
        main_layout.addLayout(input_layout)

        self.context_menu = QMenu(self)
        copy_action = QAction("Copy", self)
        copy_action.triggered.connect(self.copy_text)
        self.context_menu.addAction(copy_action)
        self.chat_area.setContextMenuPolicy(Qt.CustomContextMenu)
        self.chat_area.customContextMenuRequested.connect(self.show_context_menu)

        threading.Thread(target=self.accept_clients, daemon=True).start()

    def accept_clients(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)

        print(f"Server started on {HOST}:{PORT}")
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                ssl_socket = context.wrap_socket(client_socket, server_side=True)
                clients.append((ssl_socket, client_address))
                print(f"Connection from {client_address}")
                threading.Thread(target=self.handle_client, args=(ssl_socket,), daemon=True).start()
            except Exception as e:
                print(f"Error accepting client: {e}")

    def handle_client(self, client_socket):
        try:
            while True:
                header = client_socket.recv(4).decode()
                if header == "TEXT":
                    name_len = int(client_socket.recv(4).decode())
                    sender = client_socket.recv(name_len).decode()
                    msg = client_socket.recv(1024).decode()
                    self.display_message(sender, msg)
                    self.broadcast_message(sender, msg)

                elif header == "FILE":
                    name_len = int(client_socket.recv(4).decode())
                    sender = client_socket.recv(name_len).decode()
                    filename_len = int(client_socket.recv(4).decode())
                    filename = client_socket.recv(filename_len).decode()
                    filesize = int(client_socket.recv(16).decode())
                    checksum = client_socket.recv(64).decode()

                    data = b''
                    while len(data) < filesize:
                        packet = client_socket.recv(min(4096, filesize - len(data)))
                        if not packet:
                            break
                        data += packet

                    with open("received_" + filename, "wb") as f:
                        f.write(data)

                    verified = calculate_checksum(data) == checksum
                    result = f"File {filename} received from {sender} {'✅ Verified' if verified else '❌ Checksum mismatch'}"
                    self.display_message("System", result)
                    self.broadcast_message("System", result)
        except Exception as e:
            print(f"Error with client: {e}")
        finally:
            client_socket.close()

    def display_message(self, sender, message, side='left'):
        style = (
            "background-color: #444444;" if side == 'right' else "background-color: #666666;"
        )
        label = f"<div align='{side}'><div style='padding:8px; border-radius:10px; margin:4px; display:inline-block; {style}'><b>{sender}</b>: {message}</div></div>"
        self.chat_area.append(label)

    def send_message(self):
        message = self.entry.text().strip()
        if message:
            try:
                self.broadcast_message(self.name, message)
                self.display_message("You", message, 'right')
            except Exception as e:
                self.display_message("System", f"Send failed: {e}", 'left')
            self.entry.clear()

    def broadcast_message(self, sender, message):
        for client_socket, _ in clients:
            try:
                client_socket.send(b"TEXT")
                client_socket.send(f"{len(sender):04}".encode())
                client_socket.send(sender.encode())
                client_socket.send(message.encode())
            except Exception as e:
                print(f"Error broadcasting message: {e}")

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self)
        if path:
            self.send_file(path)

    def send_file(self, path):
        try:
            with open(path, "rb") as f:
                data = f.read()

            filename = os.path.basename(path)
            checksum = calculate_checksum(data)
            for client_socket, _ in clients:
                try:
                    client_socket.send(b"FILE")
                    client_socket.send(f"{len(self.name):04}".encode())
                    client_socket.send(self.name.encode())
                    client_socket.send(f"{len(filename):04}".encode())
                    client_socket.send(filename.encode())
                    client_socket.send(f"{len(data):016}".encode())
                    client_socket.send(checksum.encode())
                    client_socket.sendall(data)
                except Exception as e:
                    self.chat_area.append(f"Error sending file to a client: {e}")

            self.chat_area.append(f"Sent file {filename} to all clients")
        except Exception as e:
            self.chat_area.append(f"Error sending file: {e}")

    def show_context_menu(self, point):
        self.context_menu.exec_(self.chat_area.mapToGlobal(point))

    def copy_text(self):
        cursor = self.chat_area.textCursor()
        selected_text = cursor.selectedText()
        QApplication.clipboard().setText(selected_text)


if __name__ == "__main__":
    app = QApplication([])
    window = ChatServerWindow()
    window.show()
    app.exec()