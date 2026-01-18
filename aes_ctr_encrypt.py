import os
import sys
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
    if len(sys.argv) < 3:
        print("Usage: python3 aes_ctr_encrypt.py <key_hex> <nonce_hex>")
        print("Example: python3 aes_ctr_encrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 00112233445566778899aabbccddeeff")
        print("Note: CTR mode requires 16-byte (32 hex characters) nonce")
        sys.exit(1)

    key_hex = sys.argv[1]
    nonce_hex = sys.argv[2]

    try:
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            print(f"Error: Key must be 32 bytes (64 hex characters). Got {len(key)} bytes.")
            sys.exit(1)
    except ValueError:
        print("Error: Invalid hex string provided for key.")
        sys.exit(1)

    try:
        nonce = bytes.fromhex(nonce_hex)
        if len(nonce) != 16:
            print(f"Error: Nonce must be 16 bytes (32 hex characters) for CTR mode. Got {len(nonce)} bytes.")
            sys.exit(1)
    except ValueError:
        print("Error: Invalid hex string provided for nonce.")
        sys.exit(1)

    print(f"AES Key: {key.hex()}")
    print(f"Nonce: {nonce.hex()}")

    cipher = AES_CTR_Encrypt(key)
    message = b"This message demonstrates CTR mode with exactly 64 byteszzzzzzzz"
    print(f"\nOriginal message: {message}")

    _, ciphertext = cipher.encrypt(message, nonce)
    print(f"\nEncryption complete!")
    print(f"Ciphertext: {ciphertext.hex()}")