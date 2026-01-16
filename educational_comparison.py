import os
from aes_ctr_encrypt import AES_CTR_Encrypt
from aes_ctr_decrypt import AES_CTR_Decrypt
from aes_gcm_encrypt import AES_GCM_Encrypt
from aes_gcm_decrypt import AES_GCM_Decrypt


def main():
    print("=== EDUCATIONAL AES CTR vs GCM COMPARISON ===")
    print("Showing block-by-block chaining of AES operations\n")

    key = b'\x00' * 32
    message = b"This message shows how AES block chaining works in both modes!"

    print(f"AES Key: {key.hex()}")
    print(f"Message: {message}")
    print(f"Message length: {len(message)} bytes ({(len(message) + 15) // 16} AES blocks)\n")

    print("=" * 80)
    print("CTR MODE: Counter Mode (Encryption Only)")
    print("=" * 80)

    ctr_encrypt = AES_CTR_Encrypt(key)
    ctr_nonce, ctr_ciphertext = ctr_encrypt.encrypt(message)

    print("\n" + "=" * 80)
    print("GCM MODE: Galois Counter Mode (Encryption + Authentication)")
    print("=" * 80)

    gcm_encrypt = AES_GCM_Encrypt(key)
    aad = b"metadata"
    gcm_nonce, gcm_ciphertext, gcm_tag = gcm_encrypt.encrypt(message, associated_data=aad)

    print("\n" + "=" * 80)
    print("COMPARISON SUMMARY")
    print("=" * 80)

    print(f"""
CTR Mode Process:
1. Generate nonce: {ctr_nonce.hex()}
2. For each block:
   - Create counter block (nonce + counter)
   - Encrypt counter block with AES → keystream
   - XOR keystream with plaintext → ciphertext
3. Output: (nonce, ciphertext)

GCM Mode Process:
1. Generate nonce: {gcm_nonce.hex()}
2. Generate auth key H = AES(0^128)
3. CTR encryption (same as above)
4. GHASH authentication:
   - Process associated data with H
   - Process ciphertext with H
   - Process length block with H
5. Encrypt GHASH result with AES(J0) → auth tag
6. Output: (nonce, ciphertext, auth_tag)

Key Differences:
- CTR: Just encryption via counter mode
- GCM: CTR encryption + GHASH authentication
- GCM adds: auth key generation, GHASH computation, tag generation
- GCM can authenticate associated data without encrypting it
""")

    print("Results:")
    print(f"CTR ciphertext: {ctr_ciphertext.hex()}")
    print(f"GCM ciphertext: {gcm_ciphertext.hex()}")
    print(f"GCM auth tag:   {gcm_tag.hex()}")

    if len(ctr_ciphertext) == len(gcm_ciphertext):
        print(f"\nCiphertext match: {ctr_ciphertext == gcm_ciphertext}")
        if ctr_ciphertext != gcm_ciphertext:
            print("(Ciphertexts differ due to different nonce/counter handling)")


if __name__ == "__main__":
    main()