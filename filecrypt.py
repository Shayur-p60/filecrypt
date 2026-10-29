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

Files can be encrypted with a key file (secret.key) or with a password.
Password mode derives the Fernet key from the password with Scrypt and a
random salt, which is stored in the file's header.

Usage (`filecrypt` once installed, or `python filecrypt.py`):
    filecrypt generate-key                      # create secret.key
    filecrypt encrypt <file>                    # -> <file>.encrypted
    filecrypt encrypt <file> --password         # prompt for a password instead
    filecrypt encrypt <dir> --recursive         # every file under <dir>
    filecrypt decrypt <file>.encrypted          # -> <file>
    filecrypt decrypt <dir> --recursive         # every .encrypted under <dir>
    filecrypt rotate-key [--dir D] [--recursive]  # new key + re-encrypt
"""

import argparse
import base64
import getpass
import os
import sys

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DEFAULT_KEY_FILE = "secret.key"
ENCRYPTED_SUFFIX = ".encrypted"
TMP_SUFFIX = ".tmp"

# Password-mode file layout: PASSWORD_MAGIC + 16-byte salt + Fernet token.
# Fernet tokens are base64 text and so can never start with these bytes,
# which is how decrypt tells password files from key-file files.
PASSWORD_MAGIC = b"FCPW\x01"
SALT_SIZE = 16
# Scrypt cost settings, as recommended by the cryptography docs.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


class WrongModeError(ValueError):
    """Raised when a file is decrypted in the wrong mode, e.g. a
    password-protected file with a key file, or the other way round."""


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


def derive_key(password: str | bytes, salt: bytes) -> bytes:
    """Derives a Fernet key from a password and salt using Scrypt."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(password))


def is_password_protected(filepath: str) -> bool:
    """True if filepath was encrypted in password mode."""
    with open(filepath, "rb") as f:
        return f.read(len(PASSWORD_MAGIC)) == PASSWORD_MAGIC


def _read_existing(filepath: str) -> bytes:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"'{filepath}' was not found.")
    with open(filepath, "rb") as f:
        return f.read()


def _write_decrypted(filepath: str, plaintext: bytes) -> str:
    if filepath.endswith(ENCRYPTED_SUFFIX):
        output_path = filepath[: -len(ENCRYPTED_SUFFIX)]
    else:
        output_path = filepath + ".decrypted"
    with open(output_path, "wb") as f:
        f.write(plaintext)
    return output_path


def encrypt_file(filepath: str, key: bytes) -> str:
    """Encrypts filepath to a separate copy and returns the copy's path.

    The original file is left untouched; the encrypted copy is written
    to '<filepath>.encrypted'.
    """
    data = _read_existing(filepath)
    output_path = filepath + ENCRYPTED_SUFFIX
    with open(output_path, "wb") as f:
        f.write(Fernet(key).encrypt(data))
    return output_path


def encrypt_file_with_password(filepath: str, password: str | bytes) -> str:
    """Like encrypt_file, but derives the key from a password.

    A fresh random salt is generated per file and stored in the output's
    header, so the same password never produces the same key twice.
    """
    data = _read_existing(filepath)
    salt = os.urandom(SALT_SIZE)
    token = Fernet(derive_key(password, salt)).encrypt(data)
    output_path = filepath + ENCRYPTED_SUFFIX
    with open(output_path, "wb") as f:
        f.write(PASSWORD_MAGIC + salt + token)
    return output_path


def decrypt_file(filepath: str, key: bytes) -> str:
    """Decrypts filepath and returns the restored file's path.

    Raises cryptography.fernet.InvalidToken if the key is wrong or the
    file has been tampered with / corrupted, and WrongModeError if the
    file is password-protected.
    """
    data = _read_existing(filepath)
    if data.startswith(PASSWORD_MAGIC):
        raise WrongModeError(
            f"'{filepath}' is password-protected. Decrypt it with a password."
        )
    plaintext = Fernet(key).decrypt(data)  # raises InvalidToken on bad key/data
    return _write_decrypted(filepath, plaintext)


def decrypt_file_with_password(filepath: str, password: str | bytes) -> str:
    """Decrypts a password-protected file and returns the restored path.

    Raises InvalidToken if the password is wrong or the file is corrupted,
    and WrongModeError if the file was encrypted with a key file.
    """
    data = _read_existing(filepath)
    if not data.startswith(PASSWORD_MAGIC):
        raise WrongModeError(
            f"'{filepath}' is not password-protected. Decrypt it with the key file."
        )
    header_size = len(PASSWORD_MAGIC) + SALT_SIZE
    if len(data) <= header_size:
        raise InvalidToken
    salt = data[len(PASSWORD_MAGIC):header_size]
    plaintext = Fernet(derive_key(password, salt)).decrypt(data[header_size:])
    return _write_decrypted(filepath, plaintext)


def _raise(error: OSError) -> None:
    raise error


def _list_files(directory: str, recursive: bool) -> list[str]:
    """Sorted paths of the regular files in directory (and below it, if
    recursive). Unreadable subdirectories raise instead of being skipped."""
    if not recursive:
        paths = (os.path.join(directory, name) for name in sorted(os.listdir(directory)))
        return [p for p in paths if os.path.isfile(p)]
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"'{directory}' is not a directory.")
    found = []
    for root, dirs, files in os.walk(directory, onerror=_raise):
        dirs.sort()
        found.extend(os.path.join(root, name) for name in sorted(files))
    return found


def find_encrypted_files(directory: str = ".", recursive: bool = False) -> list[str]:
    """Paths of the '*.encrypted' files in directory (and below, if recursive)."""
    return [p for p in _list_files(directory, recursive) if p.endswith(ENCRYPTED_SUFFIX)]


def encrypt_directory(
    directory: str,
    key: bytes | None = None,
    password: str | bytes | None = None,
    exclude: tuple[str, ...] = (),
) -> list[str]:
    """Encrypts every file under directory (recursively) with either key or
    password. Already-encrypted files, leftover temp files and any path in
    `exclude` (e.g. the key file) are skipped. Returns the new paths.
    """
    if (key is None) == (password is None):
        raise ValueError("Pass exactly one of key or password.")
    excluded = {os.path.realpath(p) for p in exclude}
    outputs = []
    for path in _list_files(directory, recursive=True):
        if (
            path.endswith(ENCRYPTED_SUFFIX)
            or path.endswith(ENCRYPTED_SUFFIX + TMP_SUFFIX)
            or os.path.realpath(path) in excluded
        ):
            continue
        try:
            if password is not None:
                outputs.append(encrypt_file_with_password(path, password))
            else:
                outputs.append(encrypt_file(path, key))
        except Exception as e:
            e.add_note(f"while encrypting '{path}'")
            raise
    return outputs


def decrypt_directory(
    directory: str,
    key: bytes | None = None,
    password: str | bytes | None = None,
) -> list[str]:
    """Decrypts every '*.encrypted' file under directory (recursively).

    Each file is decrypted in the mode it was encrypted with: password
    files use `password`, key-file files use `key`. Returns the restored
    paths. Stops at the first failure; files already restored stay restored,
    and the .encrypted copies are never modified.
    """
    outputs = []
    for path in find_encrypted_files(directory, recursive=True):
        try:
            if is_password_protected(path):
                if password is None:
                    raise WrongModeError(f"'{path}' is password-protected, but no password was given.")
                outputs.append(decrypt_file_with_password(path, password))
            else:
                if key is None:
                    raise WrongModeError(f"'{path}' needs the key file, but no key was given.")
                outputs.append(decrypt_file(path, key))
        except Exception as e:
            e.add_note(f"while decrypting '{path}'")
            raise
    return outputs


def _write_bytes(path: str, data: bytes) -> None:
    """Writes data to path and flushes it to disk before returning."""
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _remove_if_exists(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def rotate_key(
    directory: str = ".", key_path: str = DEFAULT_KEY_FILE, recursive: bool = False
) -> tuple[bytes, list[str]]:
    """Rotates the encryption key: generates a fresh key and re-encrypts
    every '*.encrypted' file in `directory` (and its subdirectories, if
    `recursive`) under it, so nothing already encrypted becomes unreadable.
    Password-protected files don't use the key file and are skipped.

    The rotation is ordered so a failure can't strand files under an
    unsaved key:
      1. Every file is decrypted with the old key first. If any fails
         (e.g. InvalidToken), nothing has been written yet.
      2. Each file is re-encrypted to '<name>.encrypted.tmp'.
      3. The old key is backed up to '<key_path>.bak', then the new key
         is written.
      4. Only then is each original replaced by its temp file via
         os.replace(), which is atomic.
    A failure before step 4 removes the temp files and leaves the
    original files and key as they were.

    Returns (new_key, list_of_rotated_filepaths).
    """
    old_key = load_key(key_path)
    old_fernet = Fernet(old_key)

    paths = [
        path
        for path in find_encrypted_files(directory, recursive)
        if not is_password_protected(path)
    ]

    # Step 1: make sure the old key opens every file before touching anything.
    # Raises InvalidToken if any file was encrypted under a different key.
    for path in paths:
        with open(path, "rb") as f:
            old_fernet.decrypt(f.read())

    new_key = Fernet.generate_key()
    new_fernet = Fernet(new_key)
    tmp_paths = []
    key_tmp_path = key_path + TMP_SUFFIX

    try:
        # Step 2: write re-encrypted copies next to the originals.
        for path in paths:
            with open(path, "rb") as f:
                plaintext = old_fernet.decrypt(f.read())
            tmp_path = path + TMP_SUFFIX
            tmp_paths.append(tmp_path)
            _write_bytes(tmp_path, new_fernet.encrypt(plaintext))

        # Step 3: back up the old key, then swap in the new one atomically.
        _write_bytes(key_path + ".bak", old_key)
        _write_bytes(key_tmp_path, new_key)
        os.replace(key_tmp_path, key_path)
    except BaseException:
        for tmp_path in tmp_paths:
            _remove_if_exists(tmp_path)
        _remove_if_exists(key_tmp_path)
        raise

    # Step 4: the new key is saved, so it's now safe to swap in the new files.
    rotated = []
    for path, tmp_path in zip(paths, tmp_paths):
        try:
            os.replace(tmp_path, path)
        except OSError as e:
            raise OSError(
                f"Rotation stopped while replacing '{path}': {e}. The new key "
                f"is in '{key_path}' and the old key is in '{key_path}.bak'. "
                f"Files already replaced use the new key; the rest still use "
                f"the old key, with new-key copies left as '*.encrypted.tmp'."
            ) from e
        rotated.append(path)

    return new_key, rotated


# --- CLI ---------------------------------------------------------------------

def _fail(message: str, error: BaseException | None = None) -> None:
    print(f"Error: {message}")
    for note in getattr(error, "__notes__", []):
        print(f"  ({note})")
    sys.exit(1)


def _prompt_password(confirm: bool) -> str:
    """Asks for a password without echoing it. Never read from argv."""
    password = getpass.getpass("Password: ")
    if not password:
        raise ValueError("Password cannot be empty.")
    if confirm and getpass.getpass("Confirm password: ") != password:
        raise ValueError("Passwords do not match.")
    return password


def _check_target(path: str, recursive: bool, action: str) -> None:
    if recursive:
        if not os.path.isdir(path):
            raise NotADirectoryError(f"'{path}' is not a directory (--recursive needs one).")
    elif os.path.isdir(path):
        raise IsADirectoryError(
            f"'{path}' is a directory. Use --recursive to {action} everything in it."
        )
    elif not os.path.exists(path):
        raise FileNotFoundError(f"'{path}' was not found.")


def _key_files(key_path: str) -> tuple[str, ...]:
    """The key file and the files rotate-key writes next to it."""
    return (key_path, key_path + ".bak", key_path + TMP_SUFFIX)


def _cli_generate_key(args):
    try:
        generate_key(args.key_file, force=args.force)
        print(f"New key generated and saved to '{args.key_file}'.")
    except FileExistsError as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cli_encrypt(args):
    try:
        _check_target(args.file, args.recursive, "encrypt")
        if args.password:
            password, key = _prompt_password(confirm=True), None
        else:
            password, key = None, load_key(args.key_file)

        if args.recursive:
            outputs = encrypt_directory(
                args.file, key=key, password=password, exclude=_key_files(args.key_file)
            )
            print(f"Encrypted {len(outputs)} file(s):")
            for output in outputs:
                print(f"  -> '{output}'")
        elif password is not None:
            print(f"Encrypted -> '{encrypt_file_with_password(args.file, password)}'")
        else:
            print(f"Encrypted -> '{encrypt_file(args.file, key)}'")
    except (OSError, ValueError) as e:
        _fail(str(e), e)


def _cli_decrypt(args):
    password = None
    try:
        _check_target(args.file, args.recursive, "decrypt")
        files = find_encrypted_files(args.file, recursive=True) if args.recursive else [args.file]
        protected = [is_password_protected(p) for p in files]

        if args.password and not any(protected):
            raise WrongModeError(
                f"Nothing password-protected found at '{args.file}'. "
                f"Run without --password to use the key file."
            )
        # Only ask for what the files actually need.
        key = load_key(args.key_file) if not all(protected) else None
        if any(protected):
            password = _prompt_password(confirm=False)

        if args.recursive:
            outputs = decrypt_directory(args.file, key=key, password=password)
            print(f"Decrypted {len(outputs)} file(s):")
            for output in outputs:
                print(f"  -> '{output}'")
        elif password is not None:
            print(f"Decrypted -> '{decrypt_file_with_password(args.file, password)}'")
        else:
            print(f"Decrypted -> '{decrypt_file(args.file, key)}'")
    except InvalidToken as e:
        if password is None:
            _fail("decryption failed. Wrong key, or the file is corrupted/not encrypted by this tool.", e)
        _fail("decryption failed. Wrong password or key, or the file is corrupted/not encrypted by this tool.", e)
    except (OSError, ValueError) as e:
        _fail(str(e), e)


def _cli_rotate_key(args):
    try:
        skipped = [
            p for p in find_encrypted_files(args.dir, args.recursive) if is_password_protected(p)
        ]
        new_key, rotated = rotate_key(
            directory=args.dir, key_path=args.key_file, recursive=args.recursive
        )
        print(f"Key rotated. Re-encrypted {len(rotated)} file(s):")
        for path in rotated:
            print(f"  - {path}")
        if skipped:
            print(f"Skipped {len(skipped)} password-protected file(s) (they don't use the key file).")
    except InvalidToken:
        print(
            "Error: a .encrypted file could not be decrypted with the current key "
            "(wrong key or corrupted). Nothing was changed."
        )
        sys.exit(1)
    except OSError as e:
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

    enc = subparsers.add_parser("encrypt", help="Encrypt a file or directory")
    enc.add_argument("file", help="Path to the file (or directory, with --recursive) to encrypt")
    enc.add_argument(
        "--password", action="store_true",
        help="Prompt for a password and derive the key from it instead of using the key file",
    )
    enc.add_argument(
        "--recursive", action="store_true",
        help="Encrypt every file in the directory and its subdirectories",
    )
    enc.set_defaults(func=_cli_encrypt)

    dec = subparsers.add_parser("decrypt", help="Decrypt a file or directory")
    dec.add_argument("file", help="Path to the .encrypted file (or directory, with --recursive)")
    dec.add_argument(
        "--password", action="store_true",
        help="Expect password-protected files. Optional: you are prompted for "
             "a password whenever a file needs one",
    )
    dec.add_argument(
        "--recursive", action="store_true",
        help="Decrypt every .encrypted file in the directory and its subdirectories",
    )
    dec.set_defaults(func=_cli_decrypt)

    rot = subparsers.add_parser(
        "rotate-key",
        help="Generate a fresh key and re-encrypt all .encrypted files under it",
    )
    rot.add_argument("--dir", default=".", help="Directory to scan for .encrypted files (default: current dir)")
    rot.add_argument("--recursive", action="store_true", help="Also rotate files in subdirectories")
    rot.set_defaults(func=_cli_rotate_key)

    return parser


def main(argv: list[str] | None = None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
