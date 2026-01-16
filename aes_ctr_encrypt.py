import os
from aes_utils import AESUtils


class AES_CTR_Encrypt:
    def __init__(self, key):
        self.utils = AESUtils(key)
        self.block_size = 16

    def _generate_keystream_block(self, nonce, counter_value):
        counter_block = self.utils.create_counter_block(nonce, counter_value)

        print(f"  Counter block {counter_value}: {counter_block.hex()}")

        keystream_block = self.utils.encrypt_block(counter_block)
        print(f"  Keystream block {counter_value}: {keystream_block.hex()}")

        return keystream_block

    def encrypt(self, plaintext, nonce=None):
        if nonce is None:
            nonce = os.urandom(16)

        print(f"\n=== CTR ENCRYPTION PROCESS ===")
        print(f"Plaintext: {plaintext}")
        print(f"Plaintext hex: {plaintext.hex()}")
        print(f"Nonce: {nonce.hex()}")
        print(f"Plaintext length: {len(plaintext)} bytes")

        num_blocks = (len(plaintext) + self.block_size - 1) // self.block_size
        print(f"Number of blocks needed: {num_blocks}")

        ciphertext = b''

        for i in range(num_blocks):
            print(f"\n--- Block {i + 1} ---")

            start_idx = i * self.block_size
            end_idx = min(start_idx + self.block_size, len(plaintext))
            plaintext_block = plaintext[start_idx:end_idx]

            print(f"  Plaintext block: {plaintext_block.hex()}")

            keystream_block = self._generate_keystream_block(nonce, i)

            ciphertext_block = self.utils.xor_bytes(plaintext_block, keystream_block)

            print(f"  XOR result: {ciphertext_block.hex()}")

            ciphertext += ciphertext_block

        print(f"\nFinal ciphertext: {ciphertext.hex()}")
        return nonce, ciphertext


if __name__ == "__main__":
    key = os.urandom(32)
    print(f"AES Key: {key.hex()}")

    cipher = AES_CTR_Encrypt(key)
    message = b"This message spans multiple AES blocks to demonstrate CTR chaining!"
    print(f"\nOriginal message: {message}")

    nonce, ciphertext = cipher.encrypt(message)
    print(f"\nEncryption complete!")
    print(f"Nonce: {nonce.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")