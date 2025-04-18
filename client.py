"""
CLIENT.PY
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

def find_prime():
    """Get a random prime number."""
    while True:
        p = random.randint(100, 500)
        if is_prime(p):
            return p

class Client:
    """Client class for encrypted chat application."""

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        """Initialize client with server connection details and username."""
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.active = True
        self.server_key = None
        self.public_key, self.private_key = self.generate_keys()
        self.s = None

    def generate_keys(self):
        """Create keys for RSA encryption."""
        p = find_prime()
        q = find_prime()
        n = p * q
        phi = (p-1) * (q-1)
        e = 65537
        d = pow(e, -1, phi)
        return (e, n), (d, n)

    def calculate_hash(self, message):
        """Calculate SHA-256 hash of the message."""
        return hashlib.sha256(message.encode()).hexdigest()

    def init_connection(self):
        """Initialize connection to server and start message handlers."""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print(f"trying to connect to {self.server_ip}:{self.port}...")
            self.s.connect((self.server_ip, self.port))
            print("connected!")
        except socket.error as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        key_data = self.s.recv(1024).decode()
        e, n = map(int, key_data.split(','))
        self.server_key = (e, n)
        our_key = f"{self.public_key[0]},{self.public_key[1]}"
        self.s.send(our_key.encode())

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.daemon = True
        message_handler.start()

        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.daemon = True
        input_handler.start()

        try:
            while self.active:
                threading.Event().wait(1)
        except KeyboardInterrupt:
            print("\nleaving chat...")
            self.active = False
        finally:
            self.s.close()

    def read_handler(self):
        """Handler for reading incoming messages."""
        while self.active:
            try:
                data = self.s.recv(4096)
                if not data:
                    print("\nlost connection")
                    self.active = False
                    break
                message_data = data.decode()
                message = ""
                try:
                    if "||" in message_data:
                        received_hash, encrypted_message = message_data.split("||", 1)
                        enc_symbs = encrypted_message.split('|')
                        decrypted_message = ""
                        for symb in enc_symbs:
                            d, n = self.private_key
                            dec_symb = pow(int(symb), d, n)
                            decrypted_message += chr(dec_symb)
                        computed_hash = self.calculate_hash(decrypted_message)
                        if computed_hash != received_hash:
                            message = "[INTEGRITY CHECK FAILED] " + decrypted_message
                        else:
                            message = decrypted_message
                    else:
                        message = message_data
                except (ValueError, TypeError, OverflowError):
                    message = message_data

                print(f"\n{message}")
                print("You: ", end="", flush=True)
            except (socket.error, ConnectionResetError, ConnectionAbortedError) as e:
                print(f"\nget message error: {e}")
                self.active = False
                break

    def write_handler(self):
        """Handler for sending outgoing messages."""

        while self.active:
            try:
                message = input("You: ")
                if message.lower() == "exit":
                    print("disconnecting...")
                    self.active = False
                    break

                if self.server_key:
                    hashed = self.calculate_hash(message)
                    encrypted = []
                    e, n = self.server_key
                    for symb in message:
                        enc_symb = pow(ord(symb), e, n)
                        encrypted.append(str(enc_symb))
                    enc_msg = '|'.join(encrypted)
                    payload = f"{hashed}||{enc_msg}"
                    self.s.send(payload.encode())
                else:
                    self.s.send(message.encode())
            except (socket.error, BrokenPipeError) as e:
                print(f"sen error: {e}")
                self.active = False
                break


if __name__ == "__main__":
    IP = "127.0.0.1"
    SERVPORT = 9001

    nameuser = input("Your username: ").strip()
    while not nameuser:
        nameuser = input("Username can't be empty!").strip()

    cl = Client(IP, SERVPORT, nameuser)
    cl.init_connection()
