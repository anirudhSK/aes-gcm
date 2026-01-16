"""
AES CTR vs GCM Mode Comparison

This file demonstrates the key differences between AES CTR and GCM modes
by running both implementations side by side.
"""

import os
from aes_ctr import AES_CTR
from aes_gcm import AES_GCM


def main():
    print("=== AES CTR vs GCM Mode Comparison ===\n")

    # Use the same key for both modes
    key = os.urandom(32)
    message = b"This is a test message to compare CTR and GCM modes"
    associated_data = b"user_id=123, session=abc"

    print(f"Original message: {message}\n")

    # === CTR MODE ===
    print("--- CTR MODE ---")
    ctr_cipher = AES_CTR(key)

    # CTR encryption
    ctr_nonce, ctr_ciphertext = ctr_cipher.encrypt(message)
    print(f"CTR Nonce (16 bytes): {ctr_nonce.hex()}")
    print(f"CTR Ciphertext: {ctr_ciphertext.hex()}")
    print("CTR Tag: None (no authentication)")

    # CTR decryption
    ctr_decrypted = ctr_cipher.decrypt(ctr_nonce, ctr_ciphertext)
    print(f"CTR Decrypted: {ctr_decrypted}")
    print(f"CTR Success: {message == ctr_decrypted}\n")

    # === GCM MODE ===
    print("--- GCM MODE ---")
    gcm_cipher = AES_GCM(key)

    # GCM encryption
    gcm_nonce, gcm_ciphertext, gcm_tag = gcm_cipher.encrypt(
        message, associated_data=associated_data
    )
    print(f"GCM Nonce (12 bytes): {gcm_nonce.hex()}")
    print(f"GCM Ciphertext: {gcm_ciphertext.hex()}")
    print(f"GCM Tag (16 bytes): {gcm_tag.hex()}")

    # GCM decryption
    gcm_decrypted = gcm_cipher.decrypt(
        gcm_nonce, gcm_ciphertext, gcm_tag, associated_data=associated_data
    )
    print(f"GCM Decrypted: {gcm_decrypted}")
    print(f"GCM Success: {message == gcm_decrypted}\n")

    # === KEY DIFFERENCES ===
    print("=== KEY DIFFERENCES ===")
    print("1. AUTHENTICATION:")
    print("   - CTR: No authentication - only encryption")
    print("   - GCM: Built-in authentication with GMAC")
    print()

    print("2. OUTPUT:")
    print("   - CTR: (nonce, ciphertext)")
    print("   - GCM: (nonce, ciphertext, authentication_tag)")
    print()

    print("3. NONCE SIZE:")
    print("   - CTR: 16 bytes (full block size)")
    print("   - GCM: 12 bytes (recommended for efficiency)")
    print()

    print("4. ASSOCIATED DATA:")
    print("   - CTR: Not supported")
    print("   - GCM: Supports authenticated associated data (AAD)")
    print()

    print("5. TAMPERING DETECTION:")
    print("   - CTR: Cannot detect tampering")
    print("   - GCM: Authentication tag detects any tampering")
    print()

    # Demonstrate tampering detection
    print("6. TAMPERING DEMONSTRATION:")

    # Try to tamper with CTR ciphertext
    tampered_ctr = bytearray(ctr_ciphertext)
    tampered_ctr[0] ^= 0xFF
    ctr_tampered_result = ctr_cipher.decrypt(ctr_nonce, bytes(tampered_ctr))
    print(f"   CTR with tampering: {ctr_tampered_result}")
    print("   ↳ CTR decrypts tampered data without error!")

    # Try to tamper with GCM ciphertext
    tampered_gcm = bytearray(gcm_ciphertext)
    tampered_gcm[0] ^= 0xFF
    try:
        gcm_cipher.decrypt(gcm_nonce, bytes(tampered_gcm), gcm_tag, associated_data)
        print("   GCM with tampering: Decryption succeeded (unexpected!)")
    except Exception as e:
        print(f"   GCM with tampering: {type(e).__name__}")
        print("   ↳ GCM detects tampering and rejects the data!")


if __name__ == "__main__":
    main()