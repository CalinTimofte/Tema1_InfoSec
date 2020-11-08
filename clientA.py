import crypto_functions, socket, pyaes

key_manager_host = "127.0.0.1"
key_manager_port = 1235

node_B_host = key_manager_host
node_B_port = 1234

own_host = key_manager_host
own_port = 1236

# Get operation mode
operation_mode = input("Enter operation mode, either 'CBC' or 'OFB'\n")
if operation_mode not in ['OFB', 'CBC']:
    raise ValueError('Please enter a correct operation mode.')

# Send operation mode to B
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((node_B_host, node_B_port))
s.send(bytes(operation_mode, 'utf-8'))
s.close()

# Send operation mode to key manager
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((key_manager_host, key_manager_port))
s.send(bytes(operation_mode, 'utf-8'))
s.close()

# Receive key from key_manager
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind((own_host, own_port))
except socket.error as e:
    print(str(e))
s.listen(1)

(connection, address) = s.accept()
data = connection.recv(100).decode("utf-8")
connection.close()

# Send the key to B
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((node_B_host, node_B_port))
s.send(bytes(data, 'utf-8'))
s.close()

# Decrypt the key
aes = pyaes.AES(crypto_functions.Kprime)
block_bytes = [ord(c) for c in data]
communication_key = aes.decrypt(block_bytes)

# Start using the key
communication_key = bytes(communication_key)

# Wait for a secure connection from B
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind((own_host, own_port))
except socket.error as e:
    print(str(e))
s.listen(1)

(connection, address) = s.accept()
message = connection.recv(1024).decode("utf-8")
if message == "Start":
    # Encrypt the file
    crypto_functions.encrypt_file('plaintext.txt', operation_mode, communication_key, crypto_functions.iv)
    # Send 1024 characters at a time
    with open('cryptotext.txt', 'rb') as crypto_file:
        crypto_text = crypto_file.read()
        crypto_text = crypto_text.decode('utf-8')
        block_list = [crypto_text[i:i + 1024] for i in range(0, len(crypto_text), 1024)]
        for block in block_list:
            connection.send(bytes(block, 'utf-8'))
connection.close()
