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


# --- rotate_key safety -------------------------------------------------------

def _snapshot(directory):
    """Maps every file name in directory to its bytes."""
    return {
        name: (directory / name).read_bytes()
        for name in os.listdir(directory)
    }


def _tmp_files(directory):
    return [name for name in os.listdir(directory) if name.endswith(".tmp")]


@pytest.fixture
def encrypted_files(tmp_path, key_path):
    """Two files encrypted under the key at key_path. Returns (key, {path: plaintext})."""
    key = filecrypt.generate_key(key_path)
    contents = {"a.txt": b"alpha contents", "b.txt": b"bravo contents"}
    encrypted = {}
    for name, data in contents.items():
        plain = tmp_path / name
        plain.write_bytes(data)
        encrypted[filecrypt.encrypt_file(str(plain), key)] = data
        plain.unlink()  # only the .encrypted copies should matter
    return key, encrypted


def test_rotate_key_success_rotates_every_file(tmp_path, key_path, encrypted_files):
    old_key, encrypted = encrypted_files

    new_key, rotated = filecrypt.rotate_key(directory=str(tmp_path), key_path=key_path)

    assert sorted(rotated) == sorted(encrypted)
    assert filecrypt.load_key(key_path) == new_key != old_key
    assert filecrypt.load_key(key_path + ".bak") == old_key
    for path, data in encrypted.items():
        with open(path, "rb") as f:
            assert Fernet(new_key).decrypt(f.read()) == data
    assert _tmp_files(tmp_path) == []


def test_rotate_key_aborts_when_a_file_uses_a_different_key(
    tmp_path, key_path, encrypted_files, monkeypatch
):
    foreign = tmp_path / "c.txt.encrypted"
    foreign.write_bytes(Fernet(Fernet.generate_key()).encrypt(b"someone else's"))
    before = _snapshot(tmp_path)

    # Force the foreign file to come last, so a rotation that rewrites as it
    # goes would already have changed a and b before failing.
    real_listdir = os.listdir
    monkeypatch.setattr(
        filecrypt.os, "listdir",
        lambda d: sorted(real_listdir(d), key=lambda n: n == foreign.name),
    )

    with pytest.raises(InvalidToken):
        filecrypt.rotate_key(directory=str(tmp_path), key_path=key_path)

    # Every file (originals and key) is byte-for-byte unchanged, nothing added.
    assert _snapshot(tmp_path) == before
    assert not os.path.exists(key_path + ".bak")
    assert _tmp_files(tmp_path) == []


def test_rotate_key_failure_while_writing_cleans_up_tmp_files(
    tmp_path, key_path, encrypted_files, monkeypatch
):
    before = _snapshot(tmp_path)
    real_write = filecrypt._write_bytes
    calls = []

    def write_then_fail(path, data):
        calls.append(path)
        if len(calls) == 2:  # first temp file written, second hits "disk full"
            raise OSError("No space left on device")
        real_write(path, data)

    monkeypatch.setattr(filecrypt, "_write_bytes", write_then_fail)

    with pytest.raises(OSError):
        filecrypt.rotate_key(directory=str(tmp_path), key_path=key_path)

    assert _snapshot(tmp_path) == before
    assert _tmp_files(tmp_path) == []
