# Net-Pro-CS-G10
23BI14452	Phạm Hoàng Việt

23BI14302	Phạm Hữu Minh

23BI14303	Trần Vũ Công Minh

23bi14376	Nguyễn Ngọc Quang

23bi14270	Nguyễn Hoàng Long

23bi14301	Đoàn Đức Minh

# Secure Chat Application (C, GTK, OpenSSL)

A secure chat application with GUI, file transfer, and authentication, written in C using GTK and OpenSSL. Supports multiple clients, message and file transfer (up to 100MB), and user confirmation before receiving files.

---

## Features
- Secure SSL/TLS communication
- GUI (GTK)
- Text messaging
- File transfer (up to 100MB)
- File integrity check (SHA-256)
- User confirmation before receiving files
- Multi-client support

---

## Requirements

### Linux/WSL
- `gcc` (build-essential)
- `libgtk-3-dev`
- `libssl-dev`
- `pkg-config`

Install dependencies:
```bash
sudo apt update
sudo apt install build-essential libgtk-3-dev libssl-dev pkg-config
```

### Windows
- Pre-built `client.exe` and required GTK/OpenSSL DLLs (see below)
- Or use WSL as above

---

## Build Instructions (Linux/WSL)

1. Clone or copy the project files to your machine.
2. Open a terminal in the `local_uxui_c` directory.
3. Build with:
   ```bash
   make
   ```

---

## Running the Application

### 1. Start the Server (Host)
```bash
./server.exe
```
- Enter your name when prompted.
- The server will display its IP address and port.

### 2. Start the Client (Friend)
- Copy `client.exe` to your friend's device (and required DLLs if on Windows).
- Open a terminal in the same directory.
- Run:
  ```bash
  ./client.exe
  ```
- Enter the server's IP address (LAN, WSL, or Radmin VPN IP) and your name.

---

## Using Radmin VPN (for Internet Connections)
1. Both host and client install [Radmin VPN](https://www.radmin-vpn.com/).
2. Create/join the same Radmin VPN network.
3. Use the Radmin VPN IP address (e.g., `26.x.x.x`) as the server IP when connecting.

---

## File Transfer & Authentication
- When a file is sent, the receiver will see a confirmation dialog.
- If accepted, the file is saved in the `received_files` directory.
- Files up to 100MB are supported.

---

## Certificate Setup (Server Only)
The server requires `cert.pem` and `key.pem` for SSL.

### 1. Create a `san.cnf` file (for Subject Alternative Names)
Create a file named `san.cnf` with the following content (edit as needed):
```ini
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = VN
ST = HANOI
L = HANOI
O = My Organization
CN = LOCALNETWORKUXUI

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = 192.168.0.108
IP.3 = 192.168.43.49
```

### 2. Generate the certificate and key using `san.cnf`
Run these commands:
```bash
openssl req -new -nodes -newkey rsa:4096 -keyout key.pem -out cert.csr -config san.cnf
openssl x509 -req -in cert.csr -signkey key.pem -out cert.pem -days 365 -extensions v3_req -extfile san.cnf
```
- This will create `key.pem` and `cert.pem` in your directory.
- You can delete `cert.csr` after.

### 3. (Alternative) Quick self-signed cert
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

---

## Notes
- Only the server needs `cert.pem` and `key.pem`.
- The client does **not** need these files.
- The `received_files` directory will be created automatically.
- For Windows, you may need to bundle GTK and OpenSSL DLLs with `client.exe`.
- For Linux/WSL, dependencies must be installed as above.

---

## Troubleshooting
- If you see GTK markup warnings, ensure you are not using HTML tags in messages.
- If you get SSL errors, check that `cert.pem` and `key.pem` exist and are readable by the server.
- For connection issues, check firewall and network settings.

---

## License
MIT License 
