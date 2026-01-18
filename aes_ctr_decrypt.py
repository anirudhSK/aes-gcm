import os
import sys
import struct
from aes_utils import AESUtils


class AES_CTR_Decrypt:
    def __init__(self, key):
        self.utils = AESUtils(key)
        self.block_size = 16

    def _generate_keystream_block(self, nonce, counter_value):
        counter_block = self.utils.create_counter_block(nonce, counter_value)

        print(f"  Counter block {counter_value}: {counter_block.hex()}")

        keystream_block = self.utils.encrypt_block(counter_block)
        print(f"  Keystream block {counter_value}: {keystream_block.hex()}")

        return keystream_block

    def decrypt(self, nonce, ciphertext):
        print(f"\n=== CTR DECRYPTION PROCESS ===")
        print(f"Ciphertext: {ciphertext.hex()}")
        print(f"Nonce: {nonce.hex()}")

        print(f"\n--- Step 1: CTR Mode Decryption ---")
        initial_counter = nonce + b'\x00\x00\x00\x01'

        num_blocks = (len(ciphertext) + 15) // 16

        plaintext = b''
        counter_value = 2

        for i in range(num_blocks):
            start_idx = i * 16
            end_idx = min(start_idx + 16, len(ciphertext))
            ciphertext_block = ciphertext[start_idx:end_idx]

            counter = nonce + struct.pack('>I', counter_value)
            keystream = self.utils.encrypt_block(counter)
            plaintext_block = self.utils.xor_bytes(ciphertext_block, keystream)

            plaintext += plaintext_block
            counter_value += 1

        print(f"  Decrypted plaintext: {plaintext}")
        return plaintext


if __name__ == "__main__":
    from aes_ctr_encrypt import AES_CTR_Encrypt

    if len(sys.argv) < 2:
        print("Usage: python3 aes_ctr_decrypt.py <key_hex>")
        print("Example: python3 aes_ctr_decrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        sys.exit(1)

    key_hex = sys.argv[1]
    try:
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            print(f"Error: Key must be 32 bytes (64 hex characters). Got {len(key)} bytes.")
            sys.exit(1)
    except ValueError:
        print("Error: Invalid hex string provided for key.")
        sys.exit(1)

    print(f"AES Key: {key.hex()}")

    encryptor = AES_CTR_Encrypt(key)
    decryptor = AES_CTR_Decrypt(key)

    message = b"This message demonstrates CTR mode with exactly 64 byteszzzzzzzz"
    print(f"\nOriginal message: {message}")

    test_nonce = bytes.fromhex("001122334455667788990011")
    nonce, ciphertext = encryptor.encrypt(message, test_nonce)
    decrypted = decryptor.decrypt(nonce, ciphertext)

    assert message == decrypted
    print("\n✓ CTR mode encryption/decryption successful!")