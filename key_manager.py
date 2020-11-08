import socket, pyaes
from crypto_functions import Kprime
from Cryptodome import Random


def safe_keygen():
    return Random.get_random_bytes(16)


own_host = '127.0.0.1'
own_port = 1235

A_host = own_host
A_port = 1236

B_host = own_host
B_port = 1234

operation_mode = None
communication_key = None

# Receive message from A
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind((own_host, own_port))
except socket.error as e:
    print(str(e))
s.listen(1)

(connection, address) = s.accept()
data = connection.recv(100).decode("utf-8")
operation_mode = data
connection.close()

# Generate key
aes = pyaes.AES(Kprime)
sending_key = safe_keygen()
encrypted_key = aes.encrypt(sending_key)
encrypted_key = ''.join([chr(i) for i in encrypted_key])

# send to A
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((A_host, A_port))
s.send(bytes(encrypted_key, 'utf-8'))
s.close()
