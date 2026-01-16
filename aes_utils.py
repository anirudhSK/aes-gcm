import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AESUtils:
    def __init__(self, key):
        self.key = key
        self.backend = default_backend()
        self.block_size = 16

    def encrypt_block(self, block):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(block) + encryptor.finalize()

    def increment_counter_32(self, counter):
        prefix = counter[:12]
        counter_val = struct.unpack('>I', counter[12:])[0]
        counter_val = (counter_val + 1) % (2**32)
        return prefix + struct.pack('>I', counter_val)

    def create_counter_block(self, nonce, counter_value):
        counter_bytes = struct.pack('>I', counter_value)
        return nonce[:12] + counter_bytes

    def xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def pad_to_block(self, data):
        padding_len = (16 - len(data) % 16) % 16
        return data + b'\x00' * padding_len