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

## Install

```bash
pip install .
```

This installs the `filecrypt` command. You can also run the script
directly without installing: `pip install -r requirements.txt`, then use
`python filecrypt.py` wherever `filecrypt` appears below.

## Usage

```bash
# 1. Generate a key (writes secret.key in the current directory)
filecrypt generate-key

# 2. Encrypt a file -> creates <file>.encrypted (the original is kept)
filecrypt encrypt notes.txt

# 3. Decrypt it back -> restores the original file
filecrypt decrypt notes.txt.encrypted

# 4. Rotate the key: generates a fresh key and re-encrypts every
#    *.encrypted file in the directory under it, so nothing already
#    encrypted becomes unreadable.
filecrypt rotate-key
```

### Password mode

Use `--password` to encrypt with a password instead of the key file. You
are prompted for it (and asked to confirm it); it is never taken as a
command-line argument, so it doesn't end up in your shell history.

```bash
filecrypt encrypt notes.txt --password
filecrypt decrypt notes.txt.encrypted     # prompts for the password
```

`decrypt` detects password-protected files on its own and only prompts
when a file needs it, so `--password` is optional there. Password mode
doesn't need `secret.key` at all.

### Whole directories

Add `--recursive` to work on a directory and everything below it:

```bash
filecrypt encrypt my_folder --recursive              # every file -> .encrypted copy
filecrypt encrypt my_folder --recursive --password   # same, one password for all
filecrypt decrypt my_folder --recursive              # every .encrypted file
filecrypt rotate-key --dir my_folder --recursive     # rotate subfolders too
```

`encrypt --recursive` skips files that are already `.encrypted` and never
encrypts the key file (or its `.bak` backup) if it lives in that folder.
A folder can mix key-file and password files: `decrypt --recursive`
handles each in its own mode.

Run `filecrypt --help` or `filecrypt <command> --help` for the full option
list (e.g. `--key-file` to use a non-default key location, `--force` to
overwrite an existing key).

## Key rotation, and why it matters

Rotating encryption keys periodically (or after any suspected exposure) is
standard security practice — it limits how much data a single compromised
key can expose. `rotate-key` here does this properly rather than just
swapping the key file: it decrypts every `.encrypted` file with the *old*
key first, then re-encrypts it with the *new* one, so existing encrypted
files stay decryptable after rotation instead of being orphaned.

Rotation is also safe if something goes wrong partway: every file is
checked against the old key before anything is written, re-encrypted
copies go to temporary files, and the originals are only replaced once
the new key is saved. The old key is kept as `secret.key.bak`; delete it
once you've confirmed your files decrypt with the new key, especially if
you rotated because the old key leaked.

Password-protected files don't use the key file, so `rotate-key` skips
them and tells you how many it skipped.

## How password mode works

The key is derived from your password with
[Scrypt](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt),
a deliberately slow, memory-hard function that makes brute-forcing
passwords expensive. Each file gets its own random 16-byte salt, so the
same password produces a different key for every file. The file layout is:

```
FCPW\x01 (5-byte header) | salt (16 bytes) | Fernet token
```

Fernet tokens are base64 text and can never start with the header bytes,
which is how `decrypt` tells password files from key-file files.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

The tests cover the full round trip (encrypt → decrypt) in both key-file
and password mode, key generation (including refusing to silently
overwrite an existing key), wrong-key and wrong-password failures,
recursive encrypt/decrypt/rotate, the packaged `filecrypt` command, and
key rotation, including that a failed rotation leaves every file and the
key untouched. CI runs this suite on every push via GitHub Actions.

## Security notes

- `secret.key` is git-ignored — never commit a real key to version
  control. Treat it like a password: if it leaks, rotate it immediately.
- In password mode, the encryption is only as strong as the password. Use
  a long, unique one. There is no way to recover a forgotten password.
- This tool is for learning/portfolio purposes. For production use,
  consider a proper secrets manager (e.g. AWS KMS, HashiCorp Vault) rather
  than a local key file.
