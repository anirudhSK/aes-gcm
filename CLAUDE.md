# AES CTR vs GCM Implementation

This project contains implementations of AES CTR and AES GCM modes to demonstrate their differences at the code level.

## Setup

1. Install the cryptography library:
   ```bash
   pip3 install cryptography
   ```

2. Use Python 3 to run the scripts:
   ```bash
   python3 comparison.py
   ```

## Files

- `aes_ctr.py` - AES CTR mode implementation (encryption only)
- `aes_gcm.py` - AES GCM mode implementation (encryption + authentication)
- `comparison.py` - Side-by-side comparison demonstrating key differences

## Running the Comparison

```bash
python3 comparison.py
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