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


# --- password mode -----------------------------------------------------------

PASSWORD = "correct horse battery staple"


def _fake_getpass(monkeypatch, *answers):
    """Makes getpass return the given answers in order, and records prompts."""
    remaining = list(answers)
    prompts = []

    def fake(prompt="Password: "):
        prompts.append(prompt)
        return remaining.pop(0)

    monkeypatch.setattr(filecrypt.getpass, "getpass", fake)
    return prompts


def test_password_round_trip(sample_file):
    original = open(sample_file, "rb").read()
    encrypted_path = filecrypt.encrypt_file_with_password(sample_file, PASSWORD)
    os.remove(sample_file)

    assert filecrypt.decrypt_file_with_password(encrypted_path, PASSWORD) == sample_file
    assert open(sample_file, "rb").read() == original


def test_password_file_has_header_and_random_salt(sample_file):
    path = filecrypt.encrypt_file_with_password(sample_file, PASSWORD)
    first = open(path, "rb").read()
    filecrypt.encrypt_file_with_password(sample_file, PASSWORD)
    second = open(path, "rb").read()

    header = len(filecrypt.PASSWORD_MAGIC)
    assert first.startswith(filecrypt.PASSWORD_MAGIC)
    assert first[header:header + filecrypt.SALT_SIZE] != second[header:header + filecrypt.SALT_SIZE]
    assert b"quick brown fox" not in first


def test_wrong_password_raises_invalid_token(sample_file):
    path = filecrypt.encrypt_file_with_password(sample_file, PASSWORD)
    with pytest.raises(InvalidToken):
        filecrypt.decrypt_file_with_password(path, "wrong password")


def test_modes_are_told_apart(sample_file, key_path):
    key = filecrypt.generate_key(key_path)
    key_file_path = filecrypt.encrypt_file(sample_file, key)
    assert not filecrypt.is_password_protected(key_file_path)
    with pytest.raises(filecrypt.WrongModeError):
        filecrypt.decrypt_file_with_password(key_file_path, PASSWORD)

    password_path = filecrypt.encrypt_file_with_password(sample_file, PASSWORD)
    assert filecrypt.is_password_protected(password_path)
    with pytest.raises(filecrypt.WrongModeError):
        filecrypt.decrypt_file(password_path, key)


def test_cli_password_round_trip_prompts_and_needs_no_key(sample_file, tmp_path, monkeypatch, capsys):
    original = open(sample_file, "rb").read()
    missing_key = str(tmp_path / "no_such.key")

    prompts = _fake_getpass(monkeypatch, PASSWORD, PASSWORD)
    filecrypt.main(["--key-file", missing_key, "encrypt", sample_file, "--password"])
    assert prompts == ["Password: ", "Confirm password: "]
    os.remove(sample_file)

    # decrypt spots the header and prompts once, even without --password
    prompts = _fake_getpass(monkeypatch, PASSWORD)
    filecrypt.main(["--key-file", missing_key, "decrypt", sample_file + ".encrypted"])
    assert prompts == ["Password: "]
    assert open(sample_file, "rb").read() == original


def test_cli_password_mismatch_writes_nothing(sample_file, monkeypatch, capsys):
    _fake_getpass(monkeypatch, PASSWORD, "something else")
    with pytest.raises(SystemExit) as exit_info:
        filecrypt.main(["encrypt", sample_file, "--password"])
    assert exit_info.value.code == 1
    assert "do not match" in capsys.readouterr().out
    assert not os.path.exists(sample_file + ".encrypted")


def test_cli_wrong_password_exits_cleanly(sample_file, monkeypatch, capsys):
    path = filecrypt.encrypt_file_with_password(sample_file, PASSWORD)
    _fake_getpass(monkeypatch, "wrong password")
    with pytest.raises(SystemExit) as exit_info:
        filecrypt.main(["decrypt", path])
    assert exit_info.value.code == 1
    assert "Wrong password" in capsys.readouterr().out


def test_cli_password_is_never_a_cli_argument(sample_file):
    # --password is a flag; a value after it is rejected by argparse.
    with pytest.raises(SystemExit):
        filecrypt.build_parser().parse_args(["encrypt", sample_file, "--password", PASSWORD])


# --- recursive ---------------------------------------------------------------

@pytest.fixture
def tree(tmp_path):
    """A directory with nested files. Returns (root, {relative path: bytes})."""
    root = tmp_path / "tree"
    files = {
        "top.txt": b"top level",
        "sub/one.txt": b"first nested",
        "sub/deeper/two.bin": bytes(range(256)),
    }
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    return root, files


def test_encrypt_and_decrypt_directory_round_trip(tree, key_path):
    root, files = tree
    key = filecrypt.generate_key(key_path)

    outputs = filecrypt.encrypt_directory(str(root), key=key)
    assert sorted(outputs) == sorted(str(root / rel) + ".encrypted" for rel in files)
    for rel in files:
        (root / rel).unlink()

    restored = filecrypt.decrypt_directory(str(root), key=key)
    assert sorted(restored) == sorted(str(root / rel) for rel in files)
    for rel, data in files.items():
        assert (root / rel).read_bytes() == data


def test_encrypt_directory_skips_encrypted_and_excluded_files(tree, key_path):
    root, files = tree
    key = filecrypt.generate_key(key_path)
    key_inside = root / "secret.key"
    key_inside.write_bytes(key)

    filecrypt.encrypt_directory(str(root), key=key, exclude=(str(key_inside),))
    second_run = filecrypt.encrypt_directory(str(root), key=key, exclude=(str(key_inside),))

    assert not (root / "secret.key.encrypted").exists()
    assert not any(p.endswith(".encrypted.encrypted") for p in second_run)
    assert len(second_run) == len(files)


def test_cli_recursive_mixed_modes_and_skips_key_file(tree, monkeypatch, capsys):
    root, files = tree
    key_inside = str(root / "secret.key")
    filecrypt.main(["--key-file", key_inside, "generate-key"])
    # top.txt with the key file, the rest with a password
    filecrypt.main(["--key-file", key_inside, "encrypt", str(root / "top.txt")])
    _fake_getpass(monkeypatch, PASSWORD, PASSWORD)
    filecrypt.main(["--key-file", key_inside, "encrypt", str(root / "sub"), "--recursive", "--password"])

    assert not os.path.exists(key_inside + ".encrypted")
    for rel in files:
        (root / rel).unlink()

    prompts = _fake_getpass(monkeypatch, PASSWORD)
    filecrypt.main(["--key-file", key_inside, "decrypt", str(root), "--recursive"])
    assert prompts == ["Password: "]  # one prompt for the whole tree
    for rel, data in files.items():
        assert (root / rel).read_bytes() == data


def test_cli_recursive_encrypt_never_encrypts_key_file(tree, capsys):
    root, files = tree
    key_inside = str(root / "secret.key")
    filecrypt.main(["--key-file", key_inside, "generate-key"])
    filecrypt.main(["--key-file", key_inside, "encrypt", str(root), "--recursive"])

    assert not os.path.exists(key_inside + ".encrypted")
    assert f"Encrypted {len(files)} file(s)" in capsys.readouterr().out


def test_cli_directory_without_recursive_is_an_error(tree, key_path, capsys):
    root, _ = tree
    filecrypt.generate_key(key_path)
    with pytest.raises(SystemExit) as exit_info:
        filecrypt.main(["--key-file", key_path, "encrypt", str(root)])
    assert exit_info.value.code == 1
    assert "--recursive" in capsys.readouterr().out


def test_rotate_key_recursive_reaches_subdirectories(tree, key_path):
    root, files = tree
    old_key = filecrypt.generate_key(key_path)
    filecrypt.encrypt_directory(str(root), key=old_key)

    new_key, rotated = filecrypt.rotate_key(directory=str(root), key_path=key_path, recursive=True)
    assert sorted(rotated) == sorted(str(root / rel) + ".encrypted" for rel in files)
    for rel, data in files.items():
        with open(str(root / rel) + ".encrypted", "rb") as f:
            assert Fernet(new_key).decrypt(f.read()) == data
    assert not [n for _, _, names in os.walk(root) for n in names if n.endswith(".tmp")]


def test_rotate_key_without_recursive_leaves_subdirectories_alone(tree, key_path):
    root, _ = tree
    old_key = filecrypt.generate_key(key_path)
    filecrypt.encrypt_directory(str(root), key=old_key)
    nested = str(root / "sub" / "one.txt.encrypted")
    nested_bytes = open(nested, "rb").read()

    _, rotated = filecrypt.rotate_key(directory=str(root), key_path=key_path)

    assert rotated == [str(root / "top.txt.encrypted")]
    assert open(nested, "rb").read() == nested_bytes


def test_rotate_key_skips_password_files(tree, key_path):
    root, _ = tree
    key = filecrypt.generate_key(key_path)
    key_mode = filecrypt.encrypt_file(str(root / "top.txt"), key)
    password_mode = filecrypt.encrypt_file_with_password(str(root / "sub" / "one.txt"), PASSWORD)
    password_bytes = open(password_mode, "rb").read()

    _, rotated = filecrypt.rotate_key(directory=str(root), key_path=key_path, recursive=True)

    assert rotated == [key_mode]
    assert open(password_mode, "rb").read() == password_bytes


# --- packaging ---------------------------------------------------------------

def test_pyproject_exposes_filecrypt_command():
    import tomllib

    pyproject = os.path.join(os.path.dirname(filecrypt.__file__), "pyproject.toml")
    with open(pyproject, "rb") as f:
        config = tomllib.load(f)

    assert config["project"]["scripts"]["filecrypt"] == "filecrypt:main"
    assert callable(filecrypt.main)
