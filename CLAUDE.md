# AES CTR vs GCM Implementation

This project contains implementations of AES CTR and AES GCM modes to demonstrate their differences at the code level.

## Setup

1. Install the cryptography library:
   ```bash
   pip3 install cryptography
   ```

2. Use Python 3 to run the scripts with a 256-bit key and nonce:
   ```bash
   # CTR mode (16-byte nonce)
   python3 aes_ctr_encrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 00112233445566778899aabbccddeeff

   # GCM mode (12-byte nonce)
   python3 aes_gcm_encrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 001122334455667788990011
   ```

## Files

- `aes_ctr_encrypt.py` - AES CTR mode encryption implementation
- `aes_ctr_decrypt.py` - AES CTR mode decryption implementation
- `aes_gcm_encrypt.py` - AES GCM mode encryption implementation
- `aes_gcm_decrypt.py` - AES GCM mode decryption implementation
- `aes_utils.py` - Utility functions for AES operations

## Running Examples

All scripts require a 256-bit AES key (64 hex characters) and a nonce:

### CTR Mode (16-byte nonce)
```bash
# Encrypt with CTR mode
python3 aes_ctr_encrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 00112233445566778899aabbccddeeff

# Decrypt with CTR mode (includes encryption for demonstration)
python3 aes_ctr_decrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

### GCM Mode (12-byte nonce)
```bash
# Encrypt with GCM mode
python3 aes_gcm_encrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 001122334455667788990011

# Decrypt with GCM mode (includes encryption for demonstration)
python3 aes_gcm_decrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

### Security Note
**⚠️ WARNING:** Providing nonces via command line is insecure in production! This is only for educational purposes to understand the algorithms. In real applications, nonces should be securely generated and never reused.

This will show:
- How CTR mode provides encryption without authentication
- How GCM mode provides both encryption and authentication
- Demonstration of tampering detection (GCM rejects tampered data, CTR does not)

## Key Differences

1. **Authentication**: CTR has none, GCM includes GMAC
2. **Output**: CTR returns `(nonce, ciphertext)`, GCM returns `(nonce, ciphertext, tag)`
3. **Nonce size**: CTR uses 16 bytes, GCM uses 12 bytes
4. **Associated data**: Only GCM supports authenticated associated data
5. **Tampering detection**: Only GCM can detect data modification