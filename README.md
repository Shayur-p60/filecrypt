# filecrypt

A small command-line tool for encrypting and decrypting files, built on
[Fernet](https://cryptography.io/en/latest/fernet/) symmetric encryption
(AES-128-CBC + HMAC-SHA256 for integrity) from Python's `cryptography`
library.

## Why Fernet, not a Caesar cipher?

A Caesar cipher shifts each character by a fixed offset — the "key" is a
single small integer, trivially brute-forced, and it gives no protection
against tampering. Fernet instead provides:

- **Real confidentiality** — AES-128 under the hood, not a substitution
  cipher.
- **Integrity checking** — every token is HMAC-signed. If a file is
  corrupted or tampered with, decryption fails loudly (`InvalidToken`)
  instead of silently returning garbage.
- **A standard, audited implementation** — rather than hand-rolling crypto,
  which is a well-known way to introduce vulnerabilities.

## Usage

```bash
pip install -r requirements.txt

# 1. Generate a key (writes secret.key in the current directory)
python filecrypt.py generate-key

# 2. Encrypt a file -> creates <file>.encrypted
python filecrypt.py encrypt notes.txt

# 3. Decrypt it back -> restores the original file
python filecrypt.py decrypt notes.txt.encrypted

# 4. Rotate the key: generates a fresh key and re-encrypts every
#    *.encrypted file in the directory under it, so nothing already
#    encrypted becomes unreadable.
python filecrypt.py rotate-key
```

Run `python filecrypt.py --help` or `python filecrypt.py <command> --help`
for the full option list (e.g. `--key-file` to use a non-default key
location, `--force` to overwrite an existing key).

## Key rotation, and why it matters

Rotating encryption keys periodically (or after any suspected exposure) is
standard security practice — it limits how much data a single compromised
key can expose. `rotate-key` here does this properly rather than just
swapping the key file: it decrypts every `.encrypted` file with the *old*
key first, then re-encrypts it with the *new* one, so existing encrypted
files stay decryptable after rotation instead of being orphaned.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

10 tests cover the full round trip (encrypt → decrypt), key generation
(including refusing to silently overwrite an existing key), wrong-key
failure handling, and key rotation (including that old ciphertext becomes
unreadable under the old key post-rotation, and readable again under the
new one). CI runs this suite on every push via GitHub Actions.

## Security notes

- `secret.key` is git-ignored — never commit a real key to version
  control. Treat it like a password: if it leaks, rotate it immediately.
- This tool is for learning/portfolio purposes. For production use,
  consider a proper secrets manager (e.g. AWS KMS, HashiCorp Vault) rather
  than a local key file.
