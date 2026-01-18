# AES CTR vs GCM Implementation

This project contains implementations of AES CTR and AES GCM modes to demonstrate their differences at the code level.

## Setup

1. Install the cryptography library:
   ```bash
   pip3 install cryptography
   ```

2. Use Python 3 to run the scripts with a 256-bit key (64 hex characters):
   ```bash
   python3 aes_ctr_encrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
   ```

## Files

- `aes_ctr_encrypt.py` - AES CTR mode encryption implementation
- `aes_ctr_decrypt.py` - AES CTR mode decryption implementation
- `aes_gcm_encrypt.py` - AES GCM mode encryption implementation
- `aes_gcm_decrypt.py` - AES GCM mode decryption implementation
- `aes_utils.py` - Utility functions for AES operations

## Running Examples

All scripts require a 256-bit AES key as a 64-character hex string:

### CTR Mode
```bash
# Encrypt with CTR mode
python3 aes_ctr_encrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

# Decrypt with CTR mode (includes encryption for demonstration)
python3 aes_ctr_decrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

### GCM Mode
```bash
# Encrypt with GCM mode
python3 aes_gcm_encrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

# Decrypt with GCM mode (includes encryption for demonstration)
python3 aes_gcm_decrypt.py 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

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