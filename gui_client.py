import socket
import ssl
import os
import threading
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton,
    QFileDialog, QMenu, QInputDialog, QHBoxLayout
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from utils import calculate_checksum

CERT_FILE = "C:/Users/phamh/projects/netpro2/cert.pem"
PORT = 12345

class ChatClientWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Client Chat")
        self.setGeometry(100, 100, 600, 500)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")

        # Ask for name
        self.name, ok = QInputDialog.getText(self, "Enter Name", "Your name:")
        if not ok or not self.name.strip():
            self.name = "Client"

        # Ask for server IP
        self.server_ip, ok = QInputDialog.getText(self, "Server IP", "Enter the server's IP address:")
        if not ok or not self.server_ip.strip():
            self.server_ip = "127.0.0.1"  # fallback

        # SSL context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_socket = context.wrap_socket(client_socket, server_hostname=self.server_ip)
        try:
            self.secure_socket.connect((self.server_ip, PORT))
        except Exception as e:
            self.init_failed_ui(str(e))
            return

        # Chat UI setup
        self.chat_area = QTextEdit(self)
        self.chat_area.setReadOnly(True)
        self.chat_area.setStyleSheet("""
            background-color: #2e2e2e;
            font-size: 14px;
            color: #ffffff;
            padding: 8px;
        """)

        self.entry = QLineEdit(self)
        self.entry.setPlaceholderText("Type your message...")
        self.entry.returnPressed.connect(self.send_message)
        self.entry.setStyleSheet("background-color: #3c3c3c; color: #ffffff;")
        self.entry.setFocus()

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)

        self.file_button = QPushButton("Send File")
        self.file_button.clicked.connect(self.select_file)

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.entry)
        input_layout.addWidget(self.send_button)
        input_layout.addWidget(self.file_button)

        layout = QVBoxLayout(self)
        layout.addWidget(self.chat_area)
        layout.addLayout(input_layout)

        # Context menu
        self.context_menu = QMenu(self)
        copy_action = QAction("Copy", self)
        copy_action.triggered.connect(self.copy_text)
        self.context_menu.addAction(copy_action)
        self.chat_area.setContextMenuPolicy(Qt.CustomContextMenu)
        self.chat_area.customContextMenuRequested.connect(self.show_context_menu)

        threading.Thread(target=self.receive_data, daemon=True).start()

    def init_failed_ui(self, error_message):
        self.chat_area = QTextEdit(self)
        self.chat_area.setReadOnly(True)
        self.chat_area.setText(f"❌ Failed to connect: {error_message}")
        layout = QVBoxLayout(self)
        layout.addWidget(self.chat_area)

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
                self.secure_socket.send(b"TEXT")
                self.secure_socket.send(f"{len(self.name):04}".encode())
                self.secure_socket.send(self.name.encode())
                self.secure_socket.send(message.encode())
                self.display_message("You", message, 'right')
            except Exception as e:
                self.display_message("System", f"Send failed: {e}", 'left')
            self.entry.clear()

    def send_file(self, path):
        try:
            with open(path, "rb") as f:
                data = f.read()
            filename = os.path.basename(path)
            self.secure_socket.send(b"FILE")
            self.secure_socket.send(f"{len(self.name):04}".encode())
            self.secure_socket.send(self.name.encode())
            self.secure_socket.send(f"{len(filename):04}".encode())
            self.secure_socket.send(filename.encode())
            self.secure_socket.send(f"{len(data):016}".encode())
            self.secure_socket.send(calculate_checksum(data).encode())
            self.secure_socket.send(data)
            self.display_message("You", f"Sent file: {filename}", 'right')
        except Exception as e:
            self.display_message("System", f"File send error: {e}", 'left')

    def receive_data(self):
        try:
            while True:
                header = self.secure_socket.recv(4).decode()
                if header == "TEXT":
                    name_len = int(self.secure_socket.recv(4).decode())
                    sender = self.secure_socket.recv(name_len).decode()
                    msg = self.secure_socket.recv(1024).decode()
                    if sender != self.name:
                        self.display_message(sender, msg, 'left')
                elif header == "FILE":
                    name_len = int(self.secure_socket.recv(4).decode())
                    sender = self.secure_socket.recv(name_len).decode()
                    filename_len = int(self.secure_socket.recv(4).decode())
                    filename = self.secure_socket.recv(filename_len).decode()
                    filesize = int(self.secure_socket.recv(16).decode())
                    checksum = self.secure_socket.recv(64).decode()

                    data = b''
                    while len(data) < filesize:
                        data += self.secure_socket.recv(min(1024, filesize - len(data)))

                    file_path = os.path.join(os.getcwd(), "received_" + filename)
                    with open(file_path, "wb") as f:
                        f.write(data)
                    print(f"File saved at {file_path}")  # Debug statement for file location

                    # Checksum verification
                    verified = calculate_checksum(data) == checksum
                    if sender != self.name:
                        self.display_message(sender, f"Sent file: {filename} ({'verified' if verified else 'corrupted'})", 'left')
        except Exception as e:
            self.display_message("System", f"Receive error: {e}", 'left')

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self)
        if path:
            self.send_file(path)

    def show_context_menu(self, point):
        self.context_menu.exec_(self.chat_area.mapToGlobal(point))

    def copy_text(self):
        cursor = self.chat_area.textCursor()
        selected_text = cursor.selectedText()
        QApplication.clipboard().setText(selected_text)


if __name__ == "__main__":
    app = QApplication([])
    window = ChatClientWindow()
    window.show()
    app.exec()