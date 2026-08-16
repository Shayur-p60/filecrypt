#!/usr/bin/env python3
"""
filecrypt — a small command-line tool for encrypting and decrypting files
using Fernet (symmetric, authenticated encryption from the `cryptography`
library).

Why Fernet instead of a Caesar cipher?
A Caesar cipher is a fixed-offset substitution — it's trivial to break with
frequency analysis and offers no real confidentiality guarantee. Fernet is
built on AES-128 in CBC mode with a SHA-256 HMAC for integrity, and a
timestamp for optional TTL-based expiry. Practically, that means:
  1. An attacker can't recover the plaintext without the key (unlike a
     Caesar cipher, where the "key" is just a small integer to brute force).
  2. Tampered ciphertext is detected and rejected (via the HMAC) rather
     than silently decrypting to garbage — this is what raises
     `InvalidToken` in this tool.

Usage:
    python filecrypt.py generate-key                # create secret.key
    python filecrypt.py encrypt <file>               # -> <file>.encrypted
    python filecrypt.py decrypt <file>.encrypted      # -> <file>
    python filecrypt.py rotate-key                    # new key + re-encrypt
"""

import argparse
import os
import sys

from cryptography.fernet import Fernet, InvalidToken

DEFAULT_KEY_FILE = "secret.key"
ENCRYPTED_SUFFIX = ".encrypted"


def generate_key(key_path: str = DEFAULT_KEY_FILE, force: bool = False) -> bytes:
    """Generates a new Fernet key and writes it to key_path.

    Raises FileExistsError if a key already exists and force is False,
    since overwriting silently would make every file encrypted under the
    old key permanently unrecoverable.
    """
    if os.path.exists(key_path) and not force:
        raise FileExistsError(
            f"'{key_path}' already exists. Pass force=True (or --force on "
            f"the CLI) to overwrite it — doing so makes anything encrypted "
            f"with the old key unrecoverable."
        )
    key = Fernet.generate_key()
    with open(key_path, "wb") as f:
        f.write(key)
    return key


def load_key(key_path: str = DEFAULT_KEY_FILE) -> bytes:
    """Loads a Fernet key from disk."""
    if not os.path.exists(key_path):
        raise FileNotFoundError(
            f"'{key_path}' not found. Run 'generate-key' first."
        )
    with open(key_path, "rb") as f:
        return f.read()


def encrypt_file(filepath: str, key: bytes) -> str:
    """Encrypts filepath in place and returns the new file's path.

    The original file is left untouched; the encrypted copy is written
    to '<filepath>.encrypted'.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"'{filepath}' was not found.")

    fernet = Fernet(key)
    with open(filepath, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)
    output_path = filepath + ENCRYPTED_SUFFIX
    with open(output_path, "wb") as f:
        f.write(encrypted)
    return output_path


def decrypt_file(filepath: str, key: bytes) -> str:
    """Decrypts filepath and returns the restored file's path.

    Raises cryptography.fernet.InvalidToken if the key is wrong or the
    file has been tampered with / corrupted.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"'{filepath}' was not found.")

    fernet = Fernet(key)
    with open(filepath, "rb") as f:
        data = f.read()

    decrypted = fernet.decrypt(data)  # raises InvalidToken on bad key/data

    if filepath.endswith(ENCRYPTED_SUFFIX):
        output_path = filepath[: -len(ENCRYPTED_SUFFIX)]
    else:
        output_path = filepath + ".decrypted"

    with open(output_path, "wb") as f:
        f.write(decrypted)
    return output_path


def rotate_key(directory: str = ".", key_path: str = DEFAULT_KEY_FILE) -> tuple[bytes, list[str]]:
    """Rotates the encryption key: generates a fresh key and re-encrypts
    every '*.encrypted' file in `directory` under it, so nothing already
    encrypted becomes unreadable.

    Returns (new_key, list_of_rotated_filepaths).
    """
    old_key = load_key(key_path)
    old_fernet = Fernet(old_key)
    new_key = Fernet.generate_key()
    new_fernet = Fernet(new_key)

    rotated = []
    for name in os.listdir(directory):
        if not name.endswith(ENCRYPTED_SUFFIX):
            continue
        full_path = os.path.join(directory, name)
        with open(full_path, "rb") as f:
            data = f.read()
        plaintext = old_fernet.decrypt(data)  # will raise InvalidToken if it wasn't ours
        re_encrypted = new_fernet.encrypt(plaintext)
        with open(full_path, "wb") as f:
            f.write(re_encrypted)
        rotated.append(full_path)

    with open(key_path, "wb") as f:
        f.write(new_key)

    return new_key, rotated


def _cli_generate_key(args):
    try:
        generate_key(args.key_file, force=args.force)
        print(f"New key generated and saved to '{args.key_file}'.")
    except FileExistsError as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cli_encrypt(args):
    try:
        key = load_key(args.key_file)
        output = encrypt_file(args.file, key)
        print(f"Encrypted -> '{output}'")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cli_decrypt(args):
    try:
        key = load_key(args.key_file)
        output = decrypt_file(args.file, key)
        print(f"Decrypted -> '{output}'")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except InvalidToken:
        print("Error: decryption failed. Wrong key, or the file is corrupted/not encrypted by this tool.")
        sys.exit(1)


def _cli_rotate_key(args):
    try:
        new_key, rotated = rotate_key(directory=args.dir, key_path=args.key_file)
        print(f"Key rotated. Re-encrypted {len(rotated)} file(s):")
        for path in rotated:
            print(f"  - {path}")
    except (FileNotFoundError, InvalidToken) as e:
        print(f"Error: {e}")
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="filecrypt",
        description="Encrypt and decrypt files with Fernet symmetric encryption.",
    )
    parser.add_argument(
        "--key-file", default=DEFAULT_KEY_FILE,
        help=f"Path to the key file (default: {DEFAULT_KEY_FILE})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen = subparsers.add_parser("generate-key", help="Generate a new encryption key")
    gen.add_argument("--force", action="store_true", help="Overwrite an existing key file")
    gen.set_defaults(func=_cli_generate_key)

    enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("file", help="Path to the file to encrypt")
    enc.set_defaults(func=_cli_encrypt)

    dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("file", help="Path to the .encrypted file to decrypt")
    dec.set_defaults(func=_cli_decrypt)

    rot = subparsers.add_parser(
        "rotate-key",
        help="Generate a fresh key and re-encrypt all .encrypted files under it",
    )
    rot.add_argument("--dir", default=".", help="Directory to scan for .encrypted files (default: current dir)")
    rot.set_defaults(func=_cli_rotate_key)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
