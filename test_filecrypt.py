"""Tests for filecrypt. Run with: pytest"""

import os
import pytest
from cryptography.fernet import Fernet, InvalidToken

import filecrypt


@pytest.fixture
def sample_file(tmp_path):
    """Creates a small text file with known content to encrypt/decrypt."""
    path = tmp_path / "sample.txt"
    path.write_text("The quick brown fox jumps over the lazy dog.")
    return str(path)


@pytest.fixture
def key_path(tmp_path):
    return str(tmp_path / "secret.key")


def test_generate_key_creates_file(key_path):
    key = filecrypt.generate_key(key_path)
    assert os.path.exists(key_path)
    # A Fernet key should be loadable by Fernet itself
    Fernet(key)  # raises if malformed


def test_generate_key_refuses_to_overwrite(key_path):
    filecrypt.generate_key(key_path)
    with pytest.raises(FileExistsError):
        filecrypt.generate_key(key_path)


def test_generate_key_force_overwrites(key_path):
    first_key = filecrypt.generate_key(key_path)
    second_key = filecrypt.generate_key(key_path, force=True)
    assert first_key != second_key


def test_load_key_missing_file_raises(tmp_path):
    missing = str(tmp_path / "nope.key")
    with pytest.raises(FileNotFoundError):
        filecrypt.load_key(missing)


def test_encrypt_creates_encrypted_file(sample_file, key_path):
    key = filecrypt.generate_key(key_path)
    output = filecrypt.encrypt_file(sample_file, key)
    assert output == sample_file + ".encrypted"
    assert os.path.exists(output)
    # ciphertext should not contain the plaintext
    with open(output, "rb") as f:
        assert b"quick brown fox" not in f.read()


def test_encrypt_decrypt_round_trip(sample_file, key_path):
    key = filecrypt.generate_key(key_path)
    original_content = open(sample_file, "rb").read()

    encrypted_path = filecrypt.encrypt_file(sample_file, key)
    decrypted_path = filecrypt.decrypt_file(encrypted_path, key)

    assert decrypted_path == sample_file  # strips .encrypted back off
    assert open(decrypted_path, "rb").read() == original_content


def test_decrypt_with_wrong_key_raises_invalid_token(sample_file, key_path):
    correct_key = filecrypt.generate_key(key_path)
    wrong_key = Fernet.generate_key()

    encrypted_path = filecrypt.encrypt_file(sample_file, correct_key)

    with pytest.raises(InvalidToken):
        filecrypt.decrypt_file(encrypted_path, wrong_key)


def test_decrypt_missing_file_raises(key_path):
    key = filecrypt.generate_key(key_path)
    with pytest.raises(FileNotFoundError):
        filecrypt.decrypt_file("does_not_exist.encrypted", key)


def test_rotate_key_reencrypts_existing_files(tmp_path, sample_file, key_path):
    old_key = filecrypt.generate_key(key_path)
    encrypted_path = filecrypt.encrypt_file(sample_file, old_key)
    original_content = open(sample_file, "rb").read()

    new_key, rotated = filecrypt.rotate_key(directory=str(tmp_path), key_path=key_path)

    assert new_key != old_key
    assert encrypted_path in rotated

    # The old key should no longer work on the (now re-encrypted) file
    with pytest.raises(InvalidToken):
        filecrypt.decrypt_file(encrypted_path, old_key)

    # The new key should decrypt it back to the original content
    decrypted_path = filecrypt.decrypt_file(encrypted_path, new_key)
    assert open(decrypted_path, "rb").read() == original_content


def test_rotate_key_with_no_encrypted_files(tmp_path, key_path):
    filecrypt.generate_key(key_path)
    new_key, rotated = filecrypt.rotate_key(directory=str(tmp_path), key_path=key_path)
    assert rotated == []
