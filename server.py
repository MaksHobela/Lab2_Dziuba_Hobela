"""
SERVER.PY
"""

import socket
import threading
import random
import hashlib

def is_prime(n):
    """Check if number is prime."""
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def get_prime():
    """Generate a random prime number."""
    while True:
        p = random.randint(100, 500)
        if is_prime(p):
            return p

class Server:
    """Server class for encrypted chat application."""

    def __init__(self, port: int) -> None:
        """Initialize server with port and prepare for connections."""
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_keys = {}
        self.public_key, self.private_key = self.generate_keys()

    def generate_keys(self):
        """Generate RSA key pair."""
        p = get_prime()
        q = get_prime()
        n = p * q
        phi = (p-1) * (q-1)
        e = 65537
        d = pow(e, -1, phi)
        return (e, n), (d, n)

    def start(self):
        """Start server and accept client connections."""
        self.s.bind((self.host, self.port))
        self.s.listen(100)
        print(f"server running at {self.host}:{self.port}")

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)
            public_key = f"{self.public_key[0]},{self.public_key[1]}"
            c.send(public_key.encode())
            client_pub_key = c.recv(1024).decode().split(',')
            e, n = int(client_pub_key[0]), int(client_pub_key[1])
            self.client_keys[c] = (e, n)
            threading.Thread(target=self.handle_client, args=(c, addr)).start()

    def calculate_hash(self, message):
        """Calculate SHA-256 hash of the message."""
        return hashlib.sha256(message.encode()).hexdigest()

    def broadcast(self, msg: str):
        """Send message to all connected clients."""
        remove_clients = []

        for client in self.clients:
            try:
                if client in self.client_keys:
                    hashed = self.calculate_hash(msg)
                    e, n = self.client_keys[client]
                    encrypted = []
                    for symb in msg:
                        enc_symb = pow(ord(symb), e, n)
                        encrypted.append(str(enc_symb))
                    enc_msg = '|'.join(encrypted)
                    payload = f"{hashed}||{enc_msg}"
                    client.send(payload.encode())
                else:
                    client.send(msg.encode())
            except (socket.error, BrokenPipeError, ConnectionResetError):
                remove_clients.append(client)

        for client in remove_clients:
            if client in self.clients:
                self.clients.remove(client)

    def handle_client(self, c: socket.socket, addr):
        """Handle communications with a specific client."""
        try:
            while True:
                data = c.recv(4096)
                if not data:
                    break
                message_data = data.decode()
                try:
                    received_hash, encrypted_message = message_data.split("||", 1)
                    enc_symbs = encrypted_message.split('|')
                    decrypted_message = ""
                    for symb in enc_symbs:
                        d, n = self.private_key
                        dec_symb = pow(int(symb), d, n)
                        decrypted_message += chr(dec_symb)
                    computed_hash = self.calculate_hash(decrypted_message)
                    if computed_hash != received_hash:
                        print("Message integrity check failed")
                        continue

                    username = self.username_lookup.get(c, "someone")
                    full = f"{username}: {decrypted_message}"
                    print(f"{full}")
                    for client in self.clients:
                        if client != c:
                            if client in self.client_keys:
                                hashed = self.calculate_hash(full)
                                e, n = self.client_keys[client]
                                encrypted = []
                                for symb in full:
                                    enc_symb = pow(ord(symb), e, n)
                                    encrypted.append(str(enc_symb))

                                enc_msg = '|'.join(encrypted)
                                payload = f"{hashed}||{enc_msg}"
                                client.send(payload.encode())
                            else:
                                client.send(data)
                except (ValueError, TypeError, OverflowError) as e:
                    print(f"error decrypting: {e}")
                    for client in self.clients:
                        if client != c:
                            client.send(data)
        except (socket.error, ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            if c in self.clients:
                username = self.username_lookup.get(c, "someone")
                self.clients.remove(c)
                if c in self.username_lookup:
                    del self.username_lookup[c]
                if c in self.client_keys:
                    del self.client_keys[c]
                self.broadcast(f"{username} left the chat")
            c.close()


if __name__ == "__main__":
    s = Server(9001)
    s.start()
