#!/usr/bin/env python3
"""
secure_exam.py - Secure examination-paper exchange (RSA-4096 + AES-256-GCM).

Pipeline (sender):
    paper -> AES-256-GCM (fresh key + fresh 96-bit nonce, metadata as AAD)
          -> session key wrapped with recipient RSA public key (OAEP / SHA-256)
          -> whole package signed with sender RSA private key (RSA-PSS / SHA-256)

Pipeline (recipient), in this exact order:
    1. parse + structural checks
    2. verify RSA-PSS signature with TRUSTED sender public key
    3. check metadata (recipient id, algorithms)
    4. unwrap session key with recipient RSA private key (OAEP)
    5. AES-GCM decrypt (verifies the authentication tag)
    6. only now is plaintext written to disk

Library: `cryptography` (pyca) - no home-made primitives.
"""
import argparse
import base64
import getpass
import json
import os
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------------------------------------------------- constants
RSA_KEY_BITS = 4096            # "large key size"
MIN_ACCEPTED_BITS = 3072       # refuse weaker keys when loading
AES_KEY_BYTES = 32             # AES-256
NONCE_BYTES = 12               # 96-bit nonce recommended for GCM
TAG_BYTES = 16                 # 128-bit GCM tag
FORMAT_ID = "EXAM-PKG"
FORMAT_VERSION = 1
ALGORITHMS = {
    "symmetric": "AES-256-GCM",
    "key_wrap": "RSA-OAEP-SHA256",
    "signature": "RSA-PSS-SHA256",
}
PACKAGE_FIELDS = {"header", "encrypted_session_key", "nonce", "ciphertext",
                  "tag", "signature"}


# ------------------------------------------------------------------- errors
class SecureExamError(Exception):
    """Base class - every rejection reason is a subclass."""

class PackageFormatError(SecureExamError): pass
class SignatureVerificationError(SecureExamError): pass
class MetadataError(SecureExamError): pass
class SessionKeyError(SecureExamError): pass
class IntegrityError(SecureExamError): pass
class KeyFileError(SecureExamError): pass


# ----------------------------------------------------------- key management
def generate_key_pair(bits: int = RSA_KEY_BITS):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()


def _write_secret(path: Path, data: bytes, overwrite: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    fd = os.open(path, flags, 0o600)           # owner read/write only
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def save_key_pair(priv, name: str, directory, passphrase: str,
                  overwrite: bool = False):
    """Private key -> PKCS#8 PEM encrypted with passphrase (mode 0600).
       Public key  -> SubjectPublicKeyInfo PEM (shareable)."""
    d = Path(directory)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()))
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_path = d / f"{name}_private.pem"
    pub_path = d / f"{name}_public.pem"
    _write_secret(priv_path, priv_pem, overwrite)
    d.mkdir(parents=True, exist_ok=True)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def _check_size(key, path):
    if key.key_size < MIN_ACCEPTED_BITS:
        raise KeyFileError(f"{path}: RSA key too small ({key.key_size} bits)")
    return key


def load_private_key(path, passphrase: str):
    try:
        key = serialization.load_pem_private_key(
            Path(path).read_bytes(), password=passphrase.encode())
    except (ValueError, TypeError) as e:
        raise KeyFileError(f"Cannot load private key {path}: {e}") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyFileError(f"{path}: not an RSA private key")
    return _check_size(key, path)


def load_public_key(path):
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (ValueError, TypeError) as e:
        raise KeyFileError(f"Cannot load public key {path}: {e}") from None
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyFileError(f"{path}: not an RSA public key")
    return _check_size(key, path)


# ------------------------------------------------------------ crypto helpers
def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)


def _pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=hashes.SHA256().digest_size)


def _canonical(obj) -> bytes:
    """Deterministic JSON bytes (used as GCM AAD and inside the signature)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def _signing_input(header: dict, enc_key: bytes, nonce: bytes,
                   ciphertext: bytes, tag: bytes) -> bytes:
    """Unambiguous encoding of EVERYTHING in the package (length-prefixed)."""
    out = bytearray(b"EXAM-PKG-SIG-v1\x00")
    for part in (_canonical(header), enc_key, nonce, ciphertext, tag):
        out += struct.pack(">Q", len(part)) + part
    return bytes(out)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s, field: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        raise PackageFormatError(f"Field '{field}' is not valid base64") from None


# ------------------------------------------------------------------ encrypt
def encrypt_file(input_path, output_path, sender_priv, recipient_pub,
                 sender_id: str, recipient_id: str) -> dict:
    plaintext = Path(input_path).read_bytes()

    header = {
        "format": FORMAT_ID,
        "version": FORMAT_VERSION,
        "package_id": str(uuid.uuid4()),
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "file_name": Path(input_path).name,
        "plaintext_size": len(plaintext),
        "algorithms": ALGORITHMS,
    }

    session_key = AESGCM.generate_key(bit_length=AES_KEY_BYTES * 8)  # fresh
    nonce = os.urandom(NONCE_BYTES)                                    # fresh
    # Header is bound to the ciphertext as AAD -> tag also covers metadata.
    ct_and_tag = AESGCM(session_key).encrypt(nonce, plaintext, _canonical(header))
    ciphertext, tag = ct_and_tag[:-TAG_BYTES], ct_and_tag[-TAG_BYTES:]

    enc_key = recipient_pub.encrypt(session_key, _oaep())
    signature = sender_priv.sign(
        _signing_input(header, enc_key, nonce, ciphertext, tag),
        _pss(), hashes.SHA256())

    package = {
        "header": header,
        "encrypted_session_key": _b64e(enc_key),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
        "tag": _b64e(tag),
        "signature": _b64e(signature),
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(package, indent=2))
    return package


# ------------------------------------------------------------------ decrypt
def decrypt_package(package_path, recipient_priv, sender_pub,
                    recipient_id: str, output_dir) -> Path:
    """Returns path of released plaintext, or raises SecureExamError.
    Plaintext is held in memory only and written AFTER all checks pass."""
    # 1. parse + structure ---------------------------------------------------
    try:
        pkg = json.loads(Path(package_path).read_text())
    except Exception:
        raise PackageFormatError("File is not a valid package (bad JSON)") from None
    if not isinstance(pkg, dict) or set(pkg) != PACKAGE_FIELDS:
        raise PackageFormatError("Package has missing or unexpected fields")
    header = pkg["header"]
    if not isinstance(header, dict):
        raise PackageFormatError("Header is malformed")
    enc_key = _b64d(pkg["encrypted_session_key"], "encrypted_session_key")
    nonce = _b64d(pkg["nonce"], "nonce")
    ciphertext = _b64d(pkg["ciphertext"], "ciphertext")
    tag = _b64d(pkg["tag"], "tag")
    signature = _b64d(pkg["signature"], "signature")
    if len(nonce) != NONCE_BYTES or len(tag) != TAG_BYTES:
        raise PackageFormatError("Nonce or tag has wrong length")

    # 2. signature over the COMPLETE package (before touching any secret) ----
    try:
        sender_pub.verify(
            signature,
            _signing_input(header, enc_key, nonce, ciphertext, tag),
            _pss(), hashes.SHA256())
    except InvalidSignature:
        raise SignatureVerificationError(
            "Signature INVALID: package was modified or was not signed by "
            "the trusted sender") from None

    # 3. metadata policy (now trustworthy because it is signed) --------------
    if header.get("format") != FORMAT_ID or header.get("version") != FORMAT_VERSION:
        raise MetadataError("Unsupported package format/version")
    if header.get("algorithms") != ALGORITHMS:
        raise MetadataError("Unexpected algorithm suite")
    if header.get("recipient_id") != recipient_id:
        raise MetadataError(
            f"Package addressed to '{header.get('recipient_id')}', "
            f"not '{recipient_id}'")

    # 4. unwrap the session key ---------------------------------------------
    try:
        session_key = recipient_priv.decrypt(enc_key, _oaep())
    except ValueError:
        raise SessionKeyError(
            "Session key cannot be recovered: wrong recipient private key") from None

    # 5. AES-GCM (tag + AAD check) ------------------------------------------
    try:
        plaintext = AESGCM(session_key).decrypt(
            nonce, ciphertext + tag, _canonical(header))
    except InvalidTag:
        raise IntegrityError(
            "GCM authentication tag INVALID: ciphertext/metadata altered") from None

    # 6. release -------------------------------------------------------------
    safe_name = Path(str(header.get("file_name", "output.bin"))).name or "output.bin"
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / safe_name
    out_path.write_bytes(plaintext)
    return out_path


# ----------------------------------------------------------------------- CLI
def _pw(prompt, env):
    return os.environ.get(env) or getpass.getpass(prompt)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Secure exam-paper exchange")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate RSA-4096 key pair")
    k.add_argument("--name", required=True)
    k.add_argument("--out-dir", required=True)

    e = sub.add_parser("encrypt", help="encrypt + sign a paper")
    e.add_argument("--input", required=True)
    e.add_argument("--output", required=True)
    e.add_argument("--sender-key", required=True)
    e.add_argument("--recipient-pub", required=True)
    e.add_argument("--sender-id", required=True)
    e.add_argument("--recipient-id", required=True)

    d = sub.add_parser("decrypt", help="verify + decrypt a package")
    d.add_argument("--package", required=True)
    d.add_argument("--recipient-key", required=True)
    d.add_argument("--sender-pub", required=True)
    d.add_argument("--recipient-id", required=True)
    d.add_argument("--out-dir", required=True)

    a = ap.parse_args(argv)
    try:
        if a.cmd == "keygen":
            priv, _ = generate_key_pair()
            p = _pw("Passphrase to protect private key: ", "EXAM_KEY_PASSPHRASE")
            print("Saved:", *save_key_pair(priv, a.name, a.out_dir, p))
        elif a.cmd == "encrypt":
            priv = load_private_key(a.sender_key,
                                    _pw("Sender key passphrase: ", "EXAM_KEY_PASSPHRASE"))
            encrypt_file(a.input, a.output, priv, load_public_key(a.recipient_pub),
                         a.sender_id, a.recipient_id)
            print("Encrypted + signed ->", a.output)
        else:
            priv = load_private_key(a.recipient_key,
                                    _pw("Recipient key passphrase: ", "EXAM_KEY_PASSPHRASE"))
            out = decrypt_package(a.package, priv, load_public_key(a.sender_pub),
                                  a.recipient_id, a.out_dir)
            print("All checks passed. Plaintext released ->", out)
    except SecureExamError as ex:
        print(f"REJECTED [{type(ex).__name__}]: {ex}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
