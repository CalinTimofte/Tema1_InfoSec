import crypto_functions, socket, pyaes

own_host = '127.0.0.1'
own_port = 1234

node_A_host = own_host
node_A_port = 1236

operation_mode = None
communication_key = None

# First connection, get mode of operation
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

# Second connection, receive key from key_manager and decrypt it
(connection, address) = s.accept()
data = connection.recv(100).decode("utf-8")
connection.close()

# Decrypt the key
aes = pyaes.AES(crypto_functions.Kprime)
block_bytes = [ord(c) for c in data]
communication_key = aes.decrypt(block_bytes)

# Start using the key
communication_key = bytes(communication_key)
aes = pyaes.AES(communication_key)

# Start communicating securely with A
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((node_A_host, node_A_port))
# Send start message
s.send(bytes('Start', 'utf-8'))
crypto_text = ''
while True:
    data = s.recv(1024).decode('utf-8')
    if not data:
        break
    crypto_text += data
s.close()

if operation_mode == 'CBC':
    plaintext = crypto_functions.cbc_decrypt(crypto_text, communication_key, crypto_functions.iv)
else:
    plaintext = crypto_functions.ofb(crypto_text, communication_key, crypto_functions.iv, decrypting=True)

print(plaintext)