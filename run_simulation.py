#!/usr/bin/env python3
"""
run_simulation.py - two-party simulation (sender / recipient / attacker) on one
computer using separate folders, plus the five required test scenarios.

    python run_simulation.py          -> builds ./workshop and writes
                                         ./workshop/test_results.txt
"""
import base64, json, shutil, sys
from pathlib import Path

import secure_exam as se

ROOT = Path(__file__).parent / "workshop"
SENDER, RECIP, ATTACK = ROOT / "sender", ROOT / "recipient", ROOT / "attacker"
CHANNEL = ROOT / "untrusted_channel"
PASS = {"sender": "Sender-demo-passphrase!1",
        "recipient": "Recipient-demo-passphrase!2",
        "attacker": "Attacker-demo-passphrase!3"}   # demo only
SENDER_ID, RECIP_ID = "faculty.alice", "coordinator.bob"

SAMPLE_PAPER = """\
CONFIDENTIAL - END-SEMESTER EXAMINATION
Course : CS301 Information Security      Duration: 3 hours      Marks: 100
Paper code (SECRET): CS301-ES-2026-MASTER-7F3A

Q1. (10) Explain the CIA triad with one real-world example for each property.
Q2. (15) Compare AES-GCM and AES-CBC+HMAC. Why is nonce reuse fatal in GCM?
Q3. (15) Describe RSA-OAEP. Why is textbook RSA unsafe for key transport?
Q4. (20) Explain RSA-PSS and why signatures are applied to the ENTIRE package.
Q5. (20) Design a hybrid encryption scheme and discuss its failure modes.
Q6. (20) Discuss key distribution: why must public keys arrive via a trusted channel?

Answer key hint (SECRET): Q3 -> mention Bleichenbacher padding-oracle attacks.
"""

LOG = []
def say(msg=""):
    print(msg); LOG.append(msg)

RESULTS = []
def record(name, passed, detail):
    RESULTS.append((name, passed))
    say(f"  -> {'PASS' if passed else 'FAIL'}: {detail}\n")

def mutate_field(src: Path, dst: Path, field: str):
    """Attacker flips one bit in a package field (header: edits file_name)."""
    pkg = json.loads(src.read_text())
    if field == "header":
        pkg["header"]["file_name"] = "answers_leaked.txt"
    else:
        raw = bytearray(base64.b64decode(pkg[field]))
        raw[len(raw) // 2] ^= 0x01
        pkg[field] = base64.b64encode(bytes(raw)).decode()
    dst.write_text(json.dumps(pkg, indent=2))

def try_decrypt(pkg, priv, sender_pub, out_dir, rid=RECIP_ID):
    """Returns (released_path | None, error | None)."""
    try:
        return se.decrypt_package(pkg, priv, sender_pub, rid, out_dir), None
    except se.SecureExamError as e:
        return None, e

def dir_is_empty(p: Path):
    return not p.exists() or not any(p.iterdir())

def main():
    if ROOT.exists():
        shutil.rmtree(ROOT)
    for d in (SENDER/"keys", SENDER/"input", SENDER/"outbox",
              SENDER/"trusted_keys", RECIP/"keys", RECIP/"trusted_keys",
              RECIP/"inbox", RECIP/"decrypted", ATTACK/"keys",
              ATTACK/"tampered", CHANNEL):
        d.mkdir(parents=True)

    say("=" * 72)
    say(" SECURE EXAMINATION-PAPER EXCHANGE - SIMULATION")
    say("=" * 72)

    # ---------------------------------------------------------- 1. keys
    say("\n[SETUP 1] Generating RSA-%d key pairs (this takes a few seconds)..." % se.RSA_KEY_BITS)
    keys = {}
    for who, folder in (("sender", SENDER), ("recipient", RECIP), ("attacker", ATTACK)):
        priv, _ = se.generate_key_pair()
        pp, pub = se.save_key_pair(priv, who, folder/"keys", PASS[who])
        keys[who] = priv
        say(f"  {who:<9} private: {pp.relative_to(ROOT)}  (encrypted PEM, chmod 600)")
        say(f"  {'':<9} public : {pub.relative_to(ROOT)}")

    # trusted public-key exchange (assumed done over a trusted channel)
    shutil.copy(SENDER/"keys"/"sender_public.pem",    RECIP/"trusted_keys"/"sender_public.pem")
    shutil.copy(RECIP/"keys"/"recipient_public.pem",  SENDER/"trusted_keys"/"recipient_public.pem")
    say("  Public keys exchanged via 'trusted channel' (copied into trusted_keys/).")

    # reload from disk, exactly as a real run would
    s_priv = se.load_private_key(SENDER/"keys"/"sender_private.pem", PASS["sender"])
    r_pub  = se.load_public_key(SENDER/"trusted_keys"/"recipient_public.pem")
    r_priv = se.load_private_key(RECIP/"keys"/"recipient_private.pem", PASS["recipient"])
    s_pub  = se.load_public_key(RECIP/"trusted_keys"/"sender_public.pem")
    a_priv = se.load_private_key(ATTACK/"keys"/"attacker_private.pem", PASS["attacker"])
    a_pub  = se.load_public_key(ATTACK/"keys"/"attacker_public.pem")

    paper = SENDER/"input"/"exam_paper.txt"
    paper.write_text(SAMPLE_PAPER)
    original = paper.read_bytes()

    # ---------------------------------------------------------- TEST 1
    say("\n" + "-" * 72)
    say("TEST 1: Authorised recipient recovers the original file")
    say("-" * 72)
    pkg1 = SENDER/"outbox"/"exam_paper.pkg.json"
    se.encrypt_file(paper, pkg1, s_priv, r_pub, SENDER_ID, RECIP_ID)
    say(f"  Sender encrypted + signed -> {pkg1.relative_to(ROOT)} ({pkg1.stat().st_size} bytes)")
    shutil.copy(pkg1, CHANNEL/pkg1.name)
    shutil.copy(CHANNEL/pkg1.name, RECIP/"inbox"/pkg1.name)
    say("  Package travelled: sender/outbox -> untrusted_channel -> recipient/inbox")
    leak = b"CS301-ES-2026-MASTER" in pkg1.read_bytes()
    say(f"  Plaintext marker visible inside package? {leak}")
    out, err = try_decrypt(RECIP/"inbox"/pkg1.name, r_priv, s_pub, RECIP/"decrypted")
    ok = out is not None and out.read_bytes() == original and not leak
    record("T1 recipient recovers file", ok,
           f"decrypted file identical to original ({len(original)} bytes)" if ok else f"error: {err}")

    # ---------------------------------------------------------- TEST 2
    say("-" * 72)
    say("TEST 2: Attacker modifies ciphertext / metadata / signature (and more)")
    say("-" * 72)
    for label, field in [("ciphertext", "ciphertext"), ("metadata (file_name)", "header"),
                         ("signature", "signature"), ("GCM tag", "tag"),
                         ("nonce", "nonce"), ("encrypted session key", "encrypted_session_key")]:
        bad = ATTACK/"tampered"/f"tampered_{field}.json"
        mutate_field(pkg1, bad, field)
        out_dir = RECIP/"rejected_probe"/field
        out, err = try_decrypt(bad, r_priv, s_pub, out_dir)
        ok = out is None and isinstance(err, se.SignatureVerificationError) and dir_is_empty(out_dir)
        say(f"  Tampered {label:<24} -> {type(err).__name__ if err else 'ACCEPTED (!)'}: {err}")
        record(f"T2 tamper {label}", ok, "rejected, no plaintext written" if ok else "NOT rejected")

    # replacement attack: attacker builds a package of his own claiming to be the sender
    forged = ATTACK/"tampered"/"forged_replacement.json"
    se.encrypt_file(paper, forged, a_priv, r_pub, SENDER_ID, RECIP_ID)
    out_dir = RECIP/"rejected_probe"/"forged"
    out, err = try_decrypt(forged, r_priv, s_pub, out_dir)
    say(f"  Replacement package signed by attacker -> {type(err).__name__ if err else 'ACCEPTED (!)'}: {err}")
    record("T2 replacement/forgery", out is None and isinstance(err, se.SignatureVerificationError),
           "forged package rejected (not signed by trusted sender)")

    # garbage / truncated file
    junk = ATTACK/"tampered"/"junk.json"; junk.write_text('{"header": 1')
    out, err = try_decrypt(junk, r_priv, s_pub, RECIP/"rejected_probe"/"junk")
    say(f"  Truncated/garbage file -> {type(err).__name__ if err else 'ACCEPTED (!)'}: {err}")
    record("T2 malformed package", out is None and isinstance(err, se.PackageFormatError),
           "malformed package rejected")

    # GCM layer on its own: attacker re-signs a tampered ciphertext with the *real*
    # sender key (e.g. compromised signer) -> the GCM tag must still catch it.
    pkg = json.loads(pkg1.read_text())
    ct = bytearray(base64.b64decode(pkg["ciphertext"])); ct[5] ^= 1
    pkg["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    sig_in = se._signing_input(pkg["header"], base64.b64decode(pkg["encrypted_session_key"]),
                               base64.b64decode(pkg["nonce"]), bytes(ct), base64.b64decode(pkg["tag"]))
    from cryptography.hazmat.primitives import hashes
    pkg["signature"] = base64.b64encode(s_priv.sign(sig_in, se._pss(), hashes.SHA256())).decode()
    resigned = ATTACK/"tampered"/"resigned_bad_ct.json"; resigned.write_text(json.dumps(pkg))
    out_dir = RECIP/"rejected_probe"/"resigned"
    out, err = try_decrypt(resigned, r_priv, s_pub, out_dir)
    say(f"  Defence-in-depth (valid signature, bad ciphertext) -> {type(err).__name__ if err else 'ACCEPTED (!)'}: {err}")
    record("T2 GCM tag as 2nd layer", out is None and isinstance(err, se.IntegrityError) and dir_is_empty(out_dir),
           "GCM tag caught the change even though the signature was valid")

    # ---------------------------------------------------------- TEST 3
    say("-" * 72)
    say("TEST 3: Recipient decrypts with an INCORRECT private key")
    say("-" * 72)
    out_dir = ATTACK/"decrypted"
    out, err = try_decrypt(pkg1, a_priv, s_pub, out_dir)
    say(f"  Attacker's private key -> {type(err).__name__ if err else 'ACCEPTED (!)'}: {err}")
    record("T3 wrong private key", out is None and isinstance(err, se.SessionKeyError) and dir_is_empty(out_dir),
           "OAEP unwrap failed, no plaintext released")

    # ---------------------------------------------------------- TEST 4
    say("-" * 72)
    say("TEST 4: Signature verification with an INCORRECT sender public key")
    say("-" * 72)
    out_dir = RECIP/"rejected_probe"/"wrong_sender_pub"
    out, err = try_decrypt(pkg1, r_priv, a_pub, out_dir)
    say(f"  Verifying with attacker's public key -> {type(err).__name__ if err else 'ACCEPTED (!)'}: {err}")
    record("T4 wrong sender public key", out is None and isinstance(err, se.SignatureVerificationError)
           and dir_is_empty(out_dir), "signature check failed, nothing decrypted")

    # ---------------------------------------------------------- TEST 5
    say("-" * 72)
    say("TEST 5: Same file encrypted twice -> different packages")
    say("-" * 72)
    p_a, p_b = SENDER/"outbox"/"run_A.pkg.json", SENDER/"outbox"/"run_B.pkg.json"
    A = se.encrypt_file(paper, p_a, s_priv, r_pub, SENDER_ID, RECIP_ID)
    B = se.encrypt_file(paper, p_b, s_priv, r_pub, SENDER_ID, RECIP_ID)
    diffs = {k: A[k] != B[k] for k in ("encrypted_session_key", "nonce", "ciphertext", "tag", "signature")}
    diffs["package_id"] = A["header"]["package_id"] != B["header"]["package_id"]
    for k, v in diffs.items():
        say(f"  {k:<22} differs: {v}")
    outA, _ = try_decrypt(p_a, r_priv, s_pub, RECIP/"decrypted"/"A")
    outB, _ = try_decrypt(p_b, r_priv, s_pub, RECIP/"decrypted"/"B")
    both = outA and outB and outA.read_bytes() == original == outB.read_bytes()
    say(f"  Both packages decrypt to the identical original: {bool(both)}")
    record("T5 fresh randomness each time", all(diffs.values()) and p_a.read_bytes() != p_b.read_bytes() and both,
           "every random component differs; both decrypt correctly")

    # ---------------------------------------------------------- summary
    say("=" * 72)
    say(" SUMMARY")
    say("=" * 72)
    for name, ok in RESULTS:
        say(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    total, passed = len(RESULTS), sum(ok for _, ok in RESULTS)
    say(f"\n  {passed}/{total} checks passed")
    (ROOT/"test_results.txt").write_text("\n".join(LOG) + "\n")
    shutil.rmtree(RECIP/"rejected_probe", ignore_errors=True)
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
