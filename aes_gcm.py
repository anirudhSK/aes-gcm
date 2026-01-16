import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AES_GCM:
    def __init__(self, key):
        """
        Initialize AES GCM mode cipher
        key: 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
        """
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext, nonce=None, associated_data=None):
        """
        Encrypt plaintext using AES GCM mode
        plaintext: bytes to encrypt
        nonce: 12-byte nonce (generated if not provided)
        associated_data: additional data to authenticate but not encrypt
        returns: (nonce, ciphertext, tag)
        """
        if nonce is None:
            nonce = os.urandom(12)  # GCM typically uses 12-byte nonces

        # GCM mode provides both encryption and authentication
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=self.backend
        )

        encryptor = cipher.encryptor()

        # Add associated data if provided (authenticated but not encrypted)
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Get the authentication tag
        tag = encryptor.tag

        return nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag, associated_data=None):
        """
        Decrypt ciphertext using AES GCM mode
        nonce: 12-byte nonce used during encryption
        ciphertext: encrypted data
        tag: authentication tag from encryption
        associated_data: same associated data used during encryption
        returns: decrypted plaintext
        raises: InvalidTag if authentication fails
        """
        # GCM decryption includes authentication verification
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),  # Tag is provided here for verification
            backend=self.backend
        )

        decryptor = cipher.decryptor()

        # Add associated data if it was used during encryption
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext


# Example usage
if __name__ == "__main__":
    # Generate a random 256-bit key
    key = os.urandom(32)

    # Create cipher instance
    cipher = AES_GCM(key)

    # Message to encrypt
    message = b"Hello, this is a secret message for GCM mode!"

    # Associated data (authenticated but not encrypted)
    aad = b"metadata: user_id=123, timestamp=2024"

    # Encrypt
    nonce, ciphertext, tag = cipher.encrypt(message, associated_data=aad)
    print(f"Original: {message}")
    print(f"Associated data: {aad}")
    print(f"Nonce: {nonce.hex()}")
    print(f"Encrypted: {ciphertext.hex()}")
    print(f"Tag: {tag.hex()}")

    # Decrypt
    decrypted = cipher.decrypt(nonce, ciphertext, tag, associated_data=aad)
    print(f"Decrypted: {decrypted}")

    # Verify
    assert message == decrypted
    print("✓ GCM mode encryption/decryption successful!")

    # Demonstrate authentication failure
    try:
        # Try to decrypt with wrong associated data
        wrong_aad = b"metadata: user_id=456, timestamp=2024"
        cipher.decrypt(nonce, ciphertext, tag, associated_data=wrong_aad)
    except Exception as e:
        print(f"✓ Authentication failed as expected: {type(e).__name__}")