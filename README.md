
# Звіт

Файл `client.py` реалізує клієнтську частину зашифрованого чату, в якому використовується **асиметричне шифрування RSA** та **SHA-256** для перевірки цілісності повідомлень. Зв’язок із сервером встановлюється через **TCP-сокети**, а для обробки читання та запису повідомлень використовуються **потоки** (`threading`).

---

## Генерація простих чисел

На початку реалізовано допоміжні функції для роботи з простими числами, які потрібні для генерації RSA-ключів:

```python
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def find_prime():
    while True:
        p = random.randint(100, 500)
        if is_prime(p):
            return p
```

`is_prime()` перевіряє, чи є число простим, а `find_prime()` генерує випадкове просте число.

---

## Клас `Client`

Вся логіка клієнта зосереджена в класі `Client`. У конструкторі задаються IP-адреса сервера, порт, ім’я користувача, генеруються ключі RSA та ініціалізується сокет.

```python
def __init__(self, server_ip: str, port: int, username: str) -> None:
    self.server_ip = server_ip
    self.port = port
    self.username = username
    self.active = True
    self.server_key = None
    self.public_key, self.private_key = self.generate_keys()
    self.s = None
```

Ключі генеруються у методі `generate_keys()`:

```python
def generate_keys(self):
    p = find_prime()
    q = find_prime()
    n = p * q
    phi = (p-1) * (q-1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)
```

---

## Підключення до сервера

Після створення екземпляра класу викликається `init_connection()`, який встановлює з’єднання з сервером і передає ключі:

```python
def init_connection(self):
    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        self.s.connect((self.server_ip, self.port))
    except socket.error as e:
        print("[client]: could not connect to server: ", e)
        return

    self.s.send(self.username.encode())

    key_data = self.s.recv(1024).decode()
    e, n = map(int, key_data.split(','))
    self.server_key = (e, n)
    our_key = f"{self.public_key[0]},{self.public_key[1]}
    self.s.send(our_key.encode())
```

---

## Потоки читання та запису

Після з’єднання запускаються два паралельні потоки:

```python
message_handler = threading.Thread(target=self.read_handler)
message_handler.daemon = True
message_handler.start()

input_handler = threading.Thread(target=self.write_handler)
input_handler.daemon = True
input_handler.start()
```

---

## Прийом повідомлень (`read_handler`)

У цьому методі реалізовано обробку отриманих повідомлень. Якщо повідомлення зашифроване (містить `||`), воно розшифровується і перевіряється його геш:

```python
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
```

Це дозволяє перевірити, чи було змінено повідомлення під час передачі.

---

## Надсилання повідомлень (`write_handler`)

У цьому методі зчитується введення користувача, хешується повідомлення, кожен символ шифрується RSA, і все надсилається як одна строка:

```python
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
```

Це дозволяє серверу потім розшифрувати повідомлення і перевірити його справжність.

---

## хеш-функція

Функція для створення хешу повідомлення використовує SHA-256 і забезпечує перевірку цілісності:

```python
def calculate_hash(self, message):
    return hashlib.sha256(message.encode()).hexdigest()
```

---

## Вхід у чат

У головному блоці задається IP, порт, вводиться ім’я користувача, створюється екземпляр клієнта і запускається з’єднання:

```python
if __name__ == "__main__":
    IP = "127.0.0.1"
    SERVPORT = 9001

    nameuser = input("Your username: ").strip()
    while not nameuser:
        nameuser = input("Username can't be empty!").strip()

    cl = Client(IP, SERVPORT, nameuser)
    cl.init_connection()
```

---

Таким чином, `client.py` реалізує повноцінного учасника зашифрованого чату. Він:

- шифрує та розшифровує повідомлення за RSA;
- перевіряє цілісність повідомлень через SHA-256;
- використовує сокети для мережевого зв’язку;
- працює з багатопоточністю для забезпечення паралельного читання й надсилання повідомлень.


# А тепер детально розберемо файл server.py, де розписано сам сервер.

```python
import socket
import threading
import random
import hashlib
```

Спочатку імпортуються чотири бібліотеки, а саме:
- socket: для створення зв'язку на сервері;
- threading: для одночасної обробки багатьох клієнтів;
- random: для допомоги генерації чисел, які будуть застосовуватися в алгоритмі RSA;
- hashlib: для гешування.

Далі можна побачити такі функції:

```python
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
```

Функція is_prime() визначає, чи є число простим методом перебору, тоді як get_prime() вибирає рандомне просте число в діапазоні від 100 до 500. Далі ми безпосередньо переходимо до класу Sever:

```python
def __init__(self, port: int) -> None:
    """Initialize server with port and prepare for connections."""
    self.host = '127.0.0.1'
    self.port = port
    self.clients = []
    self.username_lookup = {}
    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.client_keys = {}
    self.public_key, self.private_key = self.generate_keys()
```

Його властивостями є:
- host та port: локальна адреса сервера;
- clients: список користувачів на сервері;
- username_lookup: словник, що зберігає імена користувачів;
- s: створення з'єднання між комп'ютерами;
- client_keys: збереження ключів клієнтів;
- public_key та private_key: публічний та приватний ключі сервера відповідно.

Далі слідує функція generate_keys, яка за принципом алгоритму RSA створює публічний та приватний ключі для сервера:

```python
def generate_keys(self):
    """Generate RSA key pair."""
    p = get_prime()
    q = get_prime()
    n = p * q
    phi = (p-1) * (q-1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)
```

А далі вже йде функція start(), яка запускає сервер:

```python
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
```

Тут:
```python
self.s.bind((self.host, self.port))
self.s.listen(100)
print(f"server running at {self.host}:{self.port}")
```

- Сервер прив'язується до певної адреси та порту;
- Вказується, що у черзі на сервери може стояти до 100 людей.

```python
while True:
    c, addr = self.s.accept()
```

- Сервер входить у нескінченний цикл, де пробує приймати користувачів, які хочуть підключитися;
- створюються c - об'єкт зв'язку з клієнтом та addr - адреса клієнта;

```python
username = c.recv(1024).decode()
print(f"{username} tries to connect")
self.broadcast(f'new person has joined: {username}')
self.username_lookup[c] = username
self.clients.append(c)
```

- Отримується ім'я користувача та виводиться повідомлення про його бажання підключитися;
- Додається ім'я користувача та зв'язок з ним до бази даних сервера;
- Додається цей же зв'язок до списку клієнтів сервера.

```python
public_key = f"{self.public_key[0]},{self.public_key[1]}"
c.send(public_key.encode())
client_pub_key = c.recv(1024).decode().split(',')
e, n = int(client_pub_key[0]), int(client_pub_key[1])
self.client_keys[c] = (e, n)
threading.Thread(target=self.handle_client, args=(c, addr)).start()
```

- Користувач та сервер обмінюються своїми публічними ключами, щоб клієнт міг доступитися до потоку серверу.

Далі йде функція гешування, яка перетворює повідомлення у гексові рядки:

```python
def calculate_hash(self, message):
    """Calculate SHA-256 hash of the message."""
    return hashlib.sha256(message.encode()).hexdigest()
```

Ця функція нам знадобиться у подальшій broadcast(), яка перевіряє повідомлення та сервер на "мертвих" клієнтів:

```python
def broadcast(self, message):
    """Send message to all connected clients."""
    to_remove = []
    
    for client in self.clients:
        try:
            if client in self.client_keys:
                hashed = self.calculate_hash(message)
                e, n = self.client_keys[client]
                encrypted = []
                
                for symb in message:
                    enc_symb = pow(ord(symb), e, n)
                    encrypted.append(str(enc_symb))
                
                enc_msg = '|'.join(encrypted)
                payload = f"{hashed}||{enc_msg}"
                client.send(payload.encode())
            else:
                client.send(message.encode())
        except:
            to_remove.append(client)
    
    for client in to_remove:
        if client in self.clients:
            self.clients.remove(client)
        if client in self.username_lookup:
            del self.username_lookup[client]
        if client in self.client_keys:
            del self.client_keys[client]
```

Вона виконує подальші функції:
- Пробує встановити зв'язок з користувачем;
- Якщо зв'язок встановити неможливо, то користувач додається до списку видалення, через що потім буде видалений зі серверу;
- Якщо ж доступ можливий, то обчислюється геш повідомлення, дістається публічний ключ клієнта та зашифровується кожен символ повідомлення за допомогою алгоритму RSA;
- Далі все об'єднується в одне повідомлення, де "||" - це роздільник між гешом та повідомленням, а "|" - роздільник між символами у повідомленні. І все це надсилається користувачу.

І тепер переходимо до останньої функції: handle_client(), яка обробляє повідомлення та сприяє роботі повідомлень загалом.

```python
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
```
А виконує вона подальші функції:
- приймає повідомлення користувача;
- розшифровує його;
- перевіряє, чи не було воно змінене;
- виводить повідомлення на екран;
- пересилає іншим користувачам з новим шифруванням;
- обробляє помилки, якщо щось пішло не так;
- прибирає клієнта, якщо той від'єднавсяю

РОЗПОДІЛ РОБОТИ:
- Оксана Дзюба: писала client.py: код та звіт;
- Максим Гобела: писав server.py: код та звіт.
