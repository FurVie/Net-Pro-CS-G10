import socket
import ssl
import os
import threading
import hashlib
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton,
    QFileDialog, QMenu, QInputDialog, QHBoxLayout, QMessageBox, QProgressBar
)
from PySide6.QtCore import Qt, QMetaObject, QEventLoop, Slot
from PySide6.QtGui import QAction
from utils import calculate_checksum

CERT_FILE = "C:/Users/phamh/projects/netpro2/cert.pem"
PORT = 12345
MAX_FILE_SIZE = 104857600  # 100MB

class ChatClientWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Client Chat")
        self.setGeometry(100, 100, 600, 550)

        self.name, _ = QInputDialog.getText(self, "Enter Username", "Username:")
        self.password, _ = QInputDialog.getText(self, "Enter Password", "Password:")
        self.server_ip, _ = QInputDialog.getText(self, "Server IP", "Enter server IP:")

        self.name = self.name or "Client"
        self.server_ip = self.server_ip or "127.0.0.1"

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_socket = context.wrap_socket(sock, server_hostname=self.server_ip)

        try:
            self.secure_socket.connect((self.server_ip, PORT))
        except Exception as e:
            self.init_failed_ui(str(e))
            return

        self.chat_area = QTextEdit(self)
        self.chat_area.setReadOnly(True)
        self.entry = QLineEdit(self)
        self.entry.setPlaceholderText("Type your message...")
        self.entry.returnPressed.connect(self.send_message)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        self.file_button = QPushButton("Send File")
        self.file_button.clicked.connect(self.select_file)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)

        layout = QVBoxLayout(self)
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.entry)
        input_layout.addWidget(self.send_button)
        input_layout.addWidget(self.file_button)

        layout.addWidget(self.chat_area)
        layout.addLayout(input_layout)
        layout.addWidget(self.progress_bar)

        self.context_menu = QMenu(self)
        action = QAction("Copy", self)
        action.triggered.connect(self.copy_text)
        self.context_menu.addAction(action)
        self.chat_area.setContextMenuPolicy(Qt.CustomContextMenu)
        self.chat_area.customContextMenuRequested.connect(self.show_context_menu)

        threading.Thread(target=self.receive_data, daemon=True).start()

    def init_failed_ui(self, error_message):
        layout = QVBoxLayout(self)
        text = QTextEdit(f"Connection failed: {error_message}")
        text.setReadOnly(True)
        layout.addWidget(text)

    def display_message(self, sender, message, side='left'):
        style = ("background-color: #444444;" if side == 'right' else "background-color: #666666;")
        label = f"<div align='{side}'><div style='padding:8px; border-radius:10px; margin:4px; display:inline-block; {style}'><b>{sender}</b>: {message}</div></div>"
        self.chat_area.append(label)

    def send_message(self):
        msg = self.entry.text().strip()
        if msg:
            try:
                self.secure_socket.send(b"TEXT")
                self.secure_socket.send(f"{len(self.name):04}".encode())
                self.secure_socket.send(self.name.encode())
                self.secure_socket.send(msg.encode())
                self.display_message("You", msg, 'right')
            except Exception as e:
                self.display_message("System", f"Send failed: {e}", 'left')
            self.entry.clear()

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self)
        if path:
            size = os.path.getsize(path)
            if size > MAX_FILE_SIZE:
                QMessageBox.critical(self, "File too large", "File exceeds 100MB limit.")
                return
            self.send_file(path)

    def send_file(self, path):
        try:
            with open(path, "rb") as f:
                data = f.read()

            filename = os.path.basename(path)
            checksum = calculate_checksum(data)
            total = len(data)

            self.secure_socket.send(b"FILE")
            self.secure_socket.send(f"{len(self.name):04}".encode())
            self.secure_socket.send(self.name.encode())
            self.secure_socket.send(f"{len(filename):04}".encode())
            self.secure_socket.send(filename.encode())
            self.secure_socket.send(f"{total:016}".encode())
            self.secure_socket.send(checksum.encode())

            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)

            sent = 0
            while sent < total:
                chunk = data[sent:sent+4096]
                self.secure_socket.send(chunk)
                sent += len(chunk)
                self.progress_bar.setValue(int(sent / total * 100))

            self.progress_bar.setVisible(False)
            self.display_message("You", f"Sent file: {filename}", 'right')

        except Exception as e:
            self.display_message("System", f"File send error: {e}", 'left')

    def ask_user_permission(self, sender, filename, filesize):
        self._file_prompt_result = None
        self._file_prompt_loop = QEventLoop()
        self._file_prompt_sender = sender
        self._file_prompt_filename = filename
        self._file_prompt_filesize = filesize

        QMetaObject.invokeMethod(self, "show_file_prompt", Qt.QueuedConnection)
        self._file_prompt_loop.exec()
        return self._file_prompt_result

    @Slot()
    def show_file_prompt(self):
        reply = QMessageBox.question(
            self,
            "Incoming File",
            f"Accept file '{self._file_prompt_filename}' ({self._file_prompt_filesize} bytes) from {self._file_prompt_sender}?",
            QMessageBox.Yes | QMessageBox.No
        )
        self._file_prompt_result = (reply == QMessageBox.Yes)
        self._file_prompt_loop.quit()

    def receive_data(self):
        try:
            while True:
                header = self.secure_socket.recv(4)
                if not header:
                    break
                header = header.decode()

                if header == "TEXT":
                    name_len_data = self.secure_socket.recv(4)
                    if not name_len_data:
                        break
                    name_len = int(name_len_data.decode())
                    sender = self.secure_socket.recv(name_len).decode()
                    msg = self.secure_socket.recv(1024).decode()
                    if sender != self.name:
                        self.display_message(sender, msg, 'left')

                elif header == "FILE":
                    try:
                        name_len = int(self.secure_socket.recv(4).decode())
                        sender = self.secure_socket.recv(name_len).decode()
                        filename_len = int(self.secure_socket.recv(4).decode())
                        filename = self.secure_socket.recv(filename_len).decode()
                        filesize = int(self.secure_socket.recv(16).decode())
                        checksum = self.secure_socket.recv(64).decode()

                        
                        data = b''
                        while len(data) < filesize:
                            chunk = self.secure_socket.recv(min(4096, filesize - len(data)))
                            if not chunk:
                                raise ConnectionError("Connection lost during file receive.")
                            data += chunk

                        
                        if not self.ask_user_permission(sender, filename, filesize):
                            self.display_message("System", f"File '{filename}' from {sender} discarded.", 'left')
                            continue

                        path = os.path.join(os.getcwd(), f"received_{filename}")
                        with open(path, "wb") as f:
                            f.write(data)

                        verified = calculate_checksum(data) == checksum
                        status = "verified" if verified else "corrupted"
                        self.display_message(sender, f"Sent file: {filename} ({status})", 'left')
                    except Exception as file_error:
                        self.display_message("System", f"File receive failed: {file_error}", 'left')

        except Exception as e:
            self.display_message("System", f"Connection closed: {e}", 'left')

    def show_context_menu(self, point):
        self.context_menu.exec_(self.chat_area.mapToGlobal(point))

    def copy_text(self):
        cursor = self.chat_area.textCursor()
        QApplication.clipboard().setText(cursor.selectedText())

if __name__ == "__main__":
    app = QApplication([])
    window = ChatClientWindow()
    window.show()
    app.exec()
