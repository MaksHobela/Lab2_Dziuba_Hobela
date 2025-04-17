import socket
import threading
import hashlib
import random
import time

def is_prime(n):
    if n <= 1: return False
    for i in range(2, int(n**0.5)+1):
        if n % i == 0: return False
    return True

def generate_prime():
    while True:
        p = random.randint(100, 300)
        if is_prime(p): return p

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(e, phi):
    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        x2, x1 = x1, x
        d, y1 = y1, y
    return d + phi if temp_phi == 1 else None

def generate_keypair():
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = modinv(e, phi)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    return [pow(ord(char), e, n) for char in plaintext]

def decrypt(private_key, ciphertext):
    d, n = private_key
    return ''.join([chr(pow(char, d, n)) for char in ciphertext])

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        print("[client] Creating socket")
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
            print("[client] Connected to server")
        except Exception as e:
            print("[client] Could not connect to server:", e)
            return

        self.s.send(self.username.encode())
        print("[client] Sent username")
        time.sleep(0.1)
        self.public_key, self.private_key = generate_keypair()
        pub_key_str = f"{self.public_key[0]},{self.public_key[1]}"
        self.s.send(pub_key_str.encode())
        print("[client] Sent public key")

        server_key = self.s.recv(1024).decode()
        print(f"[client] Received server public key: {server_key}")
        e, n = map(int, server_key.split(','))
        self.remote_public_key = (e, n)

        threading.Thread(target=self.read_handler, daemon=True).start()
        print("[client] Started read_handler")

        while True:
            print("[client] Waiting for input:")
            message = input()
            message_hash = hashlib.sha256(message.encode()).hexdigest()
            encrypted_nums = encrypt(self.remote_public_key, message)
            encrypted_str = ','.join(map(str, encrypted_nums))
            full_message = f"{message_hash}|{encrypted_str}"
            self.s.send(full_message.encode())

    def read_handler(self): 
        while True:
            try:
                message = self.s.recv(4096).decode()
                if not message:
                    continue
                hash_received, encrypted_data = message.split('|')
                encrypted_nums = list(map(int, encrypted_data.split(',')))
                decrypted_message = decrypt(self.private_key, encrypted_nums)
                hash_check = hashlib.sha256(decrypted_message.encode()).hexdigest()
                if hash_check == hash_received:
                    print(f"[SECURE] {decrypted_message}")
                else:
                    print(f"[WARNING] Possible tampering! Message: {decrypted_message}")
            except Exception as e:
                print(f"[client] Error while receiving message: {e}")

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
