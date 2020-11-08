import pyaes, os

# Secrets known to both node A and B
Kprime = b'\x8a\xccF\xbb\xab\x80DK\x97\x7f\xbeB\xec\x9acH'
iv = b'\x06\x83\xaf\xf8\xd4:\x04G\xa7\x82h0\xdea\xae\xbc'


def keygen():
    return os.urandom(16)


def pad(plaintext, block_size=16):
    if len(plaintext) % block_size == 0:
        return plaintext
    pad_num = block_size - (len(plaintext) % block_size)
    plaintext += pad_num * chr(pad_num)
    return plaintext


def unpad(plaintext, block_size=16):
    last_char = plaintext[-1]
    # If the last char isn't a pad character it means the text wasn't padded
    if ord(last_char) > block_size - 1:
        return plaintext
    return_text = plaintext[:-(ord(last_char))]
    return return_text


def block_feeder(plaintext, block_size=16):
    plaintext = pad(plaintext, block_size)
    block_list = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    return block_list


def cbc_encrypt(plaintext, key, iv):
    # Separate the text into blocks
    blocks = block_feeder(plaintext)

    # Where the cipher tet will be held for return
    cipher_text = ''
    aes = pyaes.AES(key)

    # Variable to retain the last encrypted block for later xoring
    last_cipher = None

    for i in range(len(blocks)):
        # If we're dealing with the first block, xor with iv, else xor with last encrypted block
        if i == 0:
            xored_block = (''.join([chr(ord(a) ^ int(b)) for a, b in zip(blocks[0], iv)]))
        else:
            xored_block = (''.join([chr(ord(a) ^ int(b)) for a, b in zip(blocks[i], last_cipher)]))
        block_bytes = [ord(c) for c in xored_block]
        last_cipher = (aes.encrypt(block_bytes))
        cipher_text += ''.join([chr(i) for i in last_cipher])
    return (cipher_text)


def cbc_decrypt(cyphertext, key, iv):
    blocks = block_feeder(cyphertext)
    plaintext = ''
    aes = pyaes.AES(key)
    last_cypher = blocks[0]
    for i in range(len(blocks)):
        block = blocks[i]
        block_bytes = [ord(c) for c in block]
        decrypted_block = aes.decrypt(block_bytes)
        decrypted_block = ''.join([chr(i) for i in decrypted_block])
        if i == 0:
            unxored_block = (''.join([chr(ord(a) ^ int(b)) for a, b in zip(decrypted_block, iv)]))
        else:
            unxored_block = (''.join([chr(ord(a) ^ ord(b)) for a, b in zip(decrypted_block, last_cypher)]))
            last_cypher = blocks[i]
        plaintext += unxored_block
    return unpad(plaintext)


def ofb(plaintext, key, iv, block_size=8, decrypting=False):
    blocks = block_feeder(plaintext, block_size)
    ciphertext = ''
    aes = pyaes.AES(key)
    for block in blocks:
        encrypted_iv = bytes(aes.encrypt(iv))
        right_side_enc_iv_bytes = encrypted_iv[:block_size]
        cipher_block = (''.join([chr(ord(a) ^ int(b)) for a, b in zip(block, iv)]))
        ciphertext += cipher_block
        iv = iv[block_size:] + right_side_enc_iv_bytes
    if decrypting:
        ciphertext = unpad(ciphertext, block_size)
    return ciphertext


def encrypt_file(filename, mode, key, iv):
    with open('cryptotext.txt', 'wb') as crypto_file:
        with open(filename, 'r') as plain_file:
            plain_text = plain_file.read()
            if mode == 'CBC':
                cyphertext = cbc_encrypt(plain_text, key, iv)
            else:
                cyphertext = ofb(plain_text, key, iv)
            crypto_file.write(bytes(cyphertext, "utf-8"))


def decrypt_file(filename, mode, key, iv):
    with open(filename, 'rb') as crypto_file:
        crypto_text = crypto_file.read()
        crypto_text = crypto_text.decode('utf-8')
        if mode == 'CBC':
            plain_text = cbc_decrypt(crypto_text, key, iv)
        else:
            plain_text = ofb(crypto_text, key, iv, decrypting=True)
    print(plain_text)
