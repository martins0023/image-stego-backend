from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import base64

# AES encryption
def encrypt_message(message, password):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_message).decode()

def decrypt_message(encrypted_message, password):
    encrypted_message = base64.b64decode(encrypted_message.encode())
    salt = encrypted_message[:16]
    iv = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]

    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode()

# Embed message into image
def embed_message(image_path, message, output_path):
    image = Image.open(image_path)
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    binary_message += '1111111111111110'  # EOF marker

    pixels = list(image.getdata())
    new_pixels = []
    message_index = 0

    for pixel in pixels:
        r, g, b = pixel[:3]
        if message_index < len(binary_message):
            r = int(bin(r)[:-1] + binary_message[message_index], 2)
            message_index += 1
        if message_index < len(binary_message):
            g = int(bin(g)[:-1] + binary_message[message_index], 2)
            message_index += 1
        if message_index < len(binary_message):
            b = int(bin(b)[:-1] + binary_message[message_index], 2)
            message_index += 1
        new_pixels.append((r, g, b) + pixel[3:])

    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_pixels)
    new_image.save(output_path)

# Extract message from image
def extract_message(image_path, password):
    image = Image.open(image_path)
    binary_message = ""
    pixels = list(image.getdata())

    for pixel in pixels:
        r, g, b = pixel[:3]
        binary_message += bin(r)[-1]
        binary_message += bin(g)[-1]
        binary_message += bin(b)[-1]

    # Remove padding and extract message
    try:
        end_index = binary_message.index('1111111111111110')
        binary_message = binary_message[:end_index]
    except ValueError:
        print("No message found in image.")
        return ""

    # Convert binary message to text
    message_bytes = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    message = ''.join([chr(int(byte, 2)) for byte in message_bytes])

    # Decrypt the message
    decrypted_message = decrypt_message(message, password)
    return decrypted_message
