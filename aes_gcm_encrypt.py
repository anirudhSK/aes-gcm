import os
import struct
from aes_utils import AESUtils


class AES_GCM_Encrypt:
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

    def _ghash(self, auth_key, associated_data, ciphertext):
        print(f"\n=== GHASH COMPUTATION ===")

        padded_aad = self.utils.pad_to_block(associated_data) if associated_data else b''
        padded_ciphertext = self.utils.pad_to_block(ciphertext)

        print(f"  Associated data: {associated_data.hex() if associated_data else '(none)'}")
        print(f"  Padded AAD: {padded_aad.hex() if padded_aad else '(none)'}")
        print(f"  Ciphertext: {ciphertext.hex()}")
        print(f"  Padded ciphertext: {padded_ciphertext.hex()}")

        ghash_state = b'\x00' * 16

        if padded_aad:
            for i in range(0, len(padded_aad), 16):
                aad_block = padded_aad[i:i+16]
                print(f"  Processing AAD block: {aad_block.hex()}")

                ghash_state = self.utils.xor_bytes(ghash_state, aad_block)
                ghash_state = self._ghash_multiply(ghash_state, auth_key)
                print(f"    GHASH state: {ghash_state.hex()}")

        for i in range(0, len(padded_ciphertext), 16):
            ct_block = padded_ciphertext[i:i+16]
            print(f"  Processing ciphertext block: {ct_block.hex()}")

            ghash_state = self.utils.xor_bytes(ghash_state, ct_block)
            ghash_state = self._ghash_multiply(ghash_state, auth_key)
            print(f"    GHASH state: {ghash_state.hex()}")

        aad_len_bits = len(associated_data) * 8 if associated_data else 0
        ct_len_bits = len(ciphertext) * 8
        len_block = struct.pack('>QQ', aad_len_bits, ct_len_bits)
        print(f"  Length block: {len_block.hex()}")

        ghash_state = self.utils.xor_bytes(ghash_state, len_block)
        ghash_state = self._ghash_multiply(ghash_state, auth_key)

        print(f"  Final GHASH: {ghash_state.hex()}")
        return ghash_state

    def encrypt(self, plaintext, nonce=None, associated_data=None):
        if nonce is None:
            nonce = os.urandom(12)

        print(f"\n=== GCM ENCRYPTION PROCESS ===")
        print(f"Plaintext: {plaintext}")
        print(f"Plaintext hex: {plaintext.hex()}")
        print(f"Nonce: {nonce.hex()}")
        print(f"Associated data: {associated_data.hex() if associated_data else '(none)'}")

        print(f"\n--- Step 1: Generate Authentication Key ---")
        auth_key = self._generate_auth_key()

        initial_counter = nonce + b'\x00\x00\x00\x01'
        print(f"  Initial counter J0: {initial_counter.hex()}")

        print(f"\n--- Step 2: CTR Mode Encryption ---")
        ciphertext = b''
        counter = self.utils.increment_counter_32(initial_counter)

        num_blocks = (len(plaintext) + 15) // 16
        print(f"Number of blocks: {num_blocks}")

        for i in range(num_blocks):
            print(f"\n  Block {i + 1}:")

            start_idx = i * 16
            end_idx = min(start_idx + 16, len(plaintext))
            pt_block = plaintext[start_idx:end_idx]
            print(f"    Plaintext block: {pt_block.hex()}")
            print(f"    Counter: {counter.hex()}")

            keystream = self.utils.encrypt_block(counter)
            print(f"    Keystream: {keystream.hex()}")

            ct_block = self.utils.xor_bytes(pt_block, keystream)
            print(f"    Ciphertext block: {ct_block.hex()}")

            ciphertext += ct_block
            counter = self.utils.increment_counter_32(counter)

        print(f"\n  Final ciphertext: {ciphertext.hex()}")

        print(f"\n--- Step 3: Authentication Tag ---")
        ghash_result = self._ghash(auth_key, associated_data, ciphertext)

        tag_keystream = self.utils.encrypt_block(initial_counter)
        print(f"  Tag keystream (AES_K(J0)): {tag_keystream.hex()}")

        auth_tag = self.utils.xor_bytes(ghash_result, tag_keystream)
        print(f"  Authentication tag: {auth_tag.hex()}")

        return nonce, ciphertext, auth_tag


if __name__ == "__main__":
    key = os.urandom(32)
    print(f"AES Key: {key.hex()}")

    cipher = AES_GCM_Encrypt(key)
    message = b"Secret GCM message!"
    aad = b"user123"

    nonce, ciphertext, tag = cipher.encrypt(message, associated_data=aad)

    print(f"\nEncryption complete!")
    print(f"Nonce: {nonce.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Auth tag: {tag.hex()}")