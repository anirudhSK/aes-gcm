import os
import sys
import struct
from aes_utils import AESUtils


class AES_GCM_Decrypt:
    def __init__(self, key):
        self.utils = AESUtils(key)
        self.block_size = 16

    def _ghash_multiply(self, x, y):
        result = 0
        x_int = int.from_bytes(x, 'big')
        y_int = int.from_bytes(y, 'big')

        for _ in range(128):
            if y_int & 1:
                result ^= x_int
            y_int >>= 1
            if x_int & (1 << 127):
                x_int = (x_int << 1) ^ 0x87
            else:
                x_int <<= 1
            x_int &= (1 << 128) - 1

        return result.to_bytes(16, 'big')

    def _generate_auth_key(self):
        zero_block = b'\x00' * 16
        auth_key = self.utils.encrypt_block(zero_block)
        print(f"  Authentication key H: {auth_key.hex()}")
        return auth_key

    def _ghash(self, auth_key, ciphertext):
        print(f"\n=== GHASH COMPUTATION ===")

        print(f"  Ciphertext: {ciphertext.hex()}")

        ghash_state = b'\x00' * 16

        for i in range(0, len(ciphertext), 16):
            ct_block = ciphertext[i:i+16]
            print(f"  Processing ciphertext block: {ct_block.hex()}")

            ghash_state = self.utils.xor_bytes(ghash_state, ct_block)
            ghash_state = self._ghash_multiply(ghash_state, auth_key)
            print(f"    GHASH state: {ghash_state.hex()}")

        ct_len_bits = len(ciphertext) * 8
        len_block = struct.pack('>QQ', 0, ct_len_bits)
        print(f"  Length block: {len_block.hex()}")

        ghash_state = self.utils.xor_bytes(ghash_state, len_block)
        ghash_state = self._ghash_multiply(ghash_state, auth_key)

        print(f"  Final GHASH: {ghash_state.hex()}")
        return ghash_state

    def decrypt(self, nonce, ciphertext, auth_tag):
        print(f"\n=== GCM DECRYPTION PROCESS ===")
        print(f"Ciphertext: {ciphertext.hex()}")
        print(f"Tag: {auth_tag.hex()}")
        print(f"Nonce: {nonce.hex()}")

        print(f"\n--- Step 1: CTR Mode Decryption ---")
        initial_counter = nonce + b'\x00\x00\x00\x01'
        plaintext = b''
        counter = self.utils.increment_counter_32(initial_counter)

        num_blocks = (len(ciphertext) + 15) // 16

        for i in range(num_blocks):
            start_idx = i * 16
            end_idx = min(start_idx + 16, len(ciphertext))
            ct_block = ciphertext[start_idx:end_idx]

            keystream = self.utils.encrypt_block(counter)
            pt_block = self.utils.xor_bytes(ct_block, keystream)

            plaintext += pt_block
            counter = self.utils.increment_counter_32(counter)

        print(f"  Decrypted plaintext: {plaintext}")

        print(f"\n--- Step 2: Verify Authentication ---")
        print(f"  Generate Authentication Key:")
        auth_key = self._generate_auth_key()

        ghash_result = self._ghash(auth_key, ciphertext)
        tag_keystream = self.utils.encrypt_block(initial_counter)
        expected_tag = self.utils.xor_bytes(ghash_result, tag_keystream)

        print(f"  Expected tag: {expected_tag.hex()}")
        print(f"  Received tag: {auth_tag.hex()}")

        if auth_tag != expected_tag:
            raise ValueError("Authentication verification failed!")
        print("  ✓ Authentication verified!")

        return plaintext


if __name__ == "__main__":
    from aes_gcm_encrypt import AES_GCM_Encrypt

    if len(sys.argv) < 2:
        print("Usage: python3 aes_gcm_decrypt.py <key_hex>")
        print("Example: python3 aes_gcm_decrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
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

    encryptor = AES_GCM_Encrypt(key)
    decryptor = AES_GCM_Decrypt(key)

    message = b"This message demonstrates CTR mode with exactly 64 byteszzzzzzzz"

    test_nonce = bytes.fromhex("001122334455667788990011")
    nonce, ciphertext, tag = encryptor.encrypt(message, test_nonce)
    decrypted = decryptor.decrypt(nonce, ciphertext, tag)

    assert message == decrypted
    print("\n✓ GCM mode encryption/decryption successful!")