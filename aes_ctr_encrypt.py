import os
import sys
import struct
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

    def encrypt(self, plaintext, nonce):
        if nonce is None:
            raise ValueError("Nonce must be provided")

        print(f"\n=== CTR ENCRYPTION PROCESS ===")
        print(f"Plaintext: {plaintext}")
        print(f"Plaintext hex: {plaintext.hex()}")
        print(f"Nonce: {nonce.hex()}")

        print(f"\n--- Step 1: CTR Mode Encryption ---")
        initial_counter = nonce + b'\x00\x00\x00\x01'
        print(f"  Initial counter J0: {initial_counter.hex()}")

        num_blocks = (len(plaintext) + 15) // 16
        print(f"Number of blocks: {num_blocks}")

        ciphertext = b''
        counter_value = 2

        for i in range(num_blocks):
            print(f"\n  Block {i + 1}:")

            start_idx = i * 16
            end_idx = min(start_idx + 16, len(plaintext))
            plaintext_block = plaintext[start_idx:end_idx]

            print(f"    Plaintext block: {plaintext_block.hex()}")

            counter = nonce + struct.pack('>I', counter_value)
            print(f"    Counter: {counter.hex()}")

            keystream = self.utils.encrypt_block(counter)
            print(f"    Keystream: {keystream.hex()}")

            ciphertext_block = self.utils.xor_bytes(plaintext_block, keystream)

            print(f"    Ciphertext block: {ciphertext_block.hex()}")

            ciphertext += ciphertext_block
            counter_value += 1

        print(f"\n  Final ciphertext: {ciphertext.hex()}")
        return nonce, ciphertext


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 aes_ctr_encrypt.py <key_hex> <nonce_hex>")
        print("Example: python3 aes_ctr_encrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 001122334455667788990011")
        print("Note: CTR mode requires 12-byte (24 hex characters) nonce")
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
        if len(nonce) != 12:
            print(f"Error: Nonce must be 12 bytes (24 hex characters) for CTR mode. Got {len(nonce)} bytes.")
            sys.exit(1)
    except ValueError:
        print("Error: Invalid hex string provided for nonce.")
        sys.exit(1)

    print(f"AES Key: {key.hex()}")
    print(f"Nonce: {nonce.hex()}")

    cipher = AES_CTR_Encrypt(key)
    message = b"This message demonstrates CTR mode with exactly 64 byteszzzzzzzz"

    _, ciphertext = cipher.encrypt(message, nonce)
    print(f"\nEncryption complete!")
    print(f"Ciphertext: {ciphertext.hex()}")
