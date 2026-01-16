import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AES_CTR:
    def __init__(self, key):
        """
        Initialize AES CTR mode cipher
        key: 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
        """
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext, nonce=None):
        """
        Encrypt plaintext using AES CTR mode
        plaintext: bytes to encrypt
        nonce: 16-byte nonce (generated if not provided)
        returns: (nonce, ciphertext)
        """
        if nonce is None:
            nonce = os.urandom(16)

        # CTR mode uses the nonce as the initial counter value
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CTR(nonce),
            backend=self.backend
        )

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return nonce, ciphertext

    def decrypt(self, nonce, ciphertext):
        """
        Decrypt ciphertext using AES CTR mode
        nonce: 16-byte nonce used during encryption
        ciphertext: encrypted data
        returns: decrypted plaintext
        """
        # CTR decryption is identical to encryption
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CTR(nonce),
            backend=self.backend
        )

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext


# Example usage
if __name__ == "__main__":
    # Generate a random 256-bit key
    key = os.urandom(32)

    # Create cipher instance
    cipher = AES_CTR(key)

    # Message to encrypt
    message = b"Hello, this is a secret message for CTR mode!"

    # Encrypt
    nonce, ciphertext = cipher.encrypt(message)
    print(f"Original: {message}")
    print(f"Nonce: {nonce.hex()}")
    print(f"Encrypted: {ciphertext.hex()}")

    # Decrypt
    decrypted = cipher.decrypt(nonce, ciphertext)
    print(f"Decrypted: {decrypted}")

    # Verify
    assert message == decrypted
    print("✓ CTR mode encryption/decryption successful!")