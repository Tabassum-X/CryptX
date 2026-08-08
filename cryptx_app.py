"""
crypto_core.py  —  the engine behind CryptX.

Every function returns a dict shaped like:
    { "ok": True, "result": {...}, "math": [ {"label": ..., "value": ...}, ... ] }
so the web layer can show BOTH the output and the underlying values
("show the math"). Real algorithms come from audited libraries
(`cryptography`, `argon2-cffi`, `kyber-py`, `dilithium-py`); only the
zero-knowledge proof and the hybrid-KDF glue are written here, and those
are standard, inspectable constructions.
"""

import base64
import hashlib
import hmac
import os
import secrets

from argon2.low_level import hash_secret_raw, Type as Argon2Type

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec, ed25519, padding, rsa, x25519,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65


# ---------- small helpers -------------------------------------------------
def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


def hx(data: bytes) -> str:
    return data.hex()


def m(label, value):
    """Build one 'math' row."""
    return {"label": label, "value": value}


def _short(hex_or_str, head=32, tail=16):
    """Abbreviate a long value for display."""
    s = hex_or_str
    if len(s) <= head + tail + 3:
        return s
    return f"{s[:head]}…{s[-tail:]}  ({len(s)} chars)"


# =========================================================================
# 1. HASHING
# =========================================================================
_HASH_ALGOS = {
    "SHA-256": (hashlib.sha256, 512, 256),
    "SHA-384": (hashlib.sha384, 1024, 384),
    "SHA-512": (hashlib.sha512, 1024, 512),
    "SHA3-256": (hashlib.sha3_256, 1088, 256),   # sponge "rate" as block-ish
    "SHA3-512": (hashlib.sha3_512, 576, 512),
    "BLAKE2b": (hashlib.blake2b, 1024, 512),
}


def do_hash(text: str, algo: str):
    if algo not in _HASH_ALGOS:
        return {"ok": False, "error": f"unknown algorithm {algo}"}
    fn, block_bits, out_bits = _HASH_ALGOS[algo]
    data = text.encode("utf-8")
    digest = fn(data).digest()

    family = "sponge (Keccak)" if algo.startswith("SHA3") else (
        "HAIFA/tree" if algo == "BLAKE2b" else "Merkle–Damgård")
    blocks = max(1, -(-len(data) * 8 // block_bits))  # ceil

    return {
        "ok": True,
        "result": {"hex": digest.hex(), "base64": b64(digest)},
        "math": [
            m("Algorithm", algo),
            m("Construction", family),
            m("Input size", f"{len(data)} bytes ({len(data) * 8} bits)"),
            m("Block / rate size", f"{block_bits} bits"),
            m("Blocks absorbed", str(blocks)),
            m("Output size", f"{out_bits} bits ({out_bits // 4} hex chars)"),
        ],
    }


# =========================================================================
# 2. KEY DERIVATION FUNCTIONS
# =========================================================================
def do_kdf(password: str, algo: str, length: int = 32):
    if not (password or ""):
        return {"ok": False, "error": "Type a password to derive a key from."}
    pw = password.encode("utf-8")
    salt = secrets.token_bytes(16)
    length = max(16, min(64, int(length)))

    if algo == "PBKDF2":
        iters = 200_000
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length,
                         salt=salt, iterations=iters)
        key = kdf.derive(pw)
        math = [
            m("Algorithm", "PBKDF2-HMAC-SHA256"),
            m("Iterations", f"{iters:,}"),
            m("Purpose", "slow password stretching"),
        ]
    elif algo == "HKDF":
        info = b"CryptX-HKDF-demo"
        kdf = HKDF(algorithm=hashes.SHA256(), length=length,
                   salt=salt, info=info)
        key = kdf.derive(pw)
        math = [
            m("Algorithm", "HKDF-SHA256"),
            m("Mode", "extract-then-expand"),
            m("Info / context", info.decode()),
            m("Purpose", "derive keys from high-entropy input"),
        ]
    elif algo == "Argon2id":
        t, mem, par = 3, 65536, 4
        key = hash_secret_raw(pw, salt, time_cost=t, memory_cost=mem,
                              parallelism=par, hash_len=length,
                              type=Argon2Type.ID)
        math = [
            m("Algorithm", "Argon2id"),
            m("Time cost (passes)", str(t)),
            m("Memory cost", f"{mem} KiB (64 MiB)"),
            m("Parallelism", str(par)),
            m("Purpose", "memory-hard password hashing (GPU-resistant)"),
        ]
    else:
        return {"ok": False, "error": f"unknown KDF {algo}"}

    return {
        "ok": True,
        "result": {"key_hex": key.hex(), "salt_hex": salt.hex()},
        "math": [m("Salt (random)", salt.hex()),
                 m("Output length", f"{length} bytes")] + math,
    }


# =========================================================================
# 3. SYMMETRIC ENCRYPTION  (AES-256-GCM, key from Argon2id)
# =========================================================================
def aes_encrypt(plaintext: str, password: str):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = hash_secret_raw(password.encode(), salt, time_cost=3,
                          memory_cost=65536, parallelism=4, hash_len=32,
                          type=Argon2Type.ID)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    tag, body = ct[-16:], ct[:-16]
    package = b64(salt + nonce + ct)  # self-contained blob
    return {
        "ok": True,
        "result": {"package": package},
        "math": [
            m("Cipher", "AES-256-GCM (authenticated encryption)"),
            m("Key derivation", "Argon2id(password, salt)"),
            m("Salt", salt.hex()),
            m("Nonce (IV, 96-bit)", nonce.hex()),
            m("Ciphertext", _short(body.hex())),
            m("Auth tag (128-bit)", tag.hex()),
            m("Package layout", "base64( salt‖nonce‖ciphertext‖tag )"),
        ],
    }


def aes_decrypt(package: str, password: str):
    try:
        raw = unb64(package)
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = hash_secret_raw(password.encode(), salt, time_cost=3,
                              memory_cost=65536, parallelism=4, hash_len=32,
                              type=Argon2Type.ID)
        pt = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        return {"ok": False,
                "error": "Decryption failed — wrong password or corrupted data "
                         "(GCM tag rejected)."}
    return {
        "ok": True,
        "result": {"plaintext": pt.decode("utf-8", "replace")},
        "math": [
            m("Cipher", "AES-256-GCM"),
            m("Tag check", "PASSED — data is authentic & untampered"),
            m("Salt", salt.hex()),
            m("Nonce", nonce.hex()),
        ],
    }


# =========================================================================
# 4. RSA  (keygen, OAEP encrypt/decrypt, PSS sign/verify)
# =========================================================================
def rsa_keygen(bits: int = 2048):
    bits = 2048 if bits not in (2048, 3072, 4096) else bits
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = key.public_key()
    nums = pub.public_numbers()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {
        "ok": True,
        "result": {"private_pem": priv_pem, "public_pem": pub_pem},
        "math": [
            m("Scheme", f"RSA-{bits}"),
            m("Public exponent e", str(nums.e)),
            m("Modulus n (bits)", str(nums.n.bit_length())),
            m("Modulus n", _short(hex(nums.n)[2:])),
            m("Security", "based on hardness of factoring n = p·q"),
        ],
    }


def rsa_encrypt(public_pem: str, plaintext: str):
    if not (public_pem or "").strip():
        return {"ok": False,
                "error": "No public key yet — click “Generate keypair” first."}
    if not (plaintext or ""):
        return {"ok": False, "error": "Type a message to encrypt first."}
    try:
        pub = serialization.load_pem_public_key(public_pem.encode())
    except Exception:
        return {"ok": False,
                "error": "That doesn’t look like a valid public key. Generate a "
                         "keypair, or paste a full PEM block including the "
                         "-----BEGIN PUBLIC KEY----- lines."}

    # RSA can only encrypt a small payload: key size minus OAEP overhead.
    max_bytes = pub.key_size // 8 - 2 * hashes.SHA256().digest_size - 2
    data = plaintext.encode("utf-8")
    if len(data) > max_bytes:
        return {"ok": False,
                "error": f"Message too long for RSA. A {pub.key_size}-bit key can "
                         f"encrypt at most {max_bytes} bytes and this is "
                         f"{len(data)}. That’s why real systems use RSA to protect "
                         f"a short AES key, then encrypt the actual message with "
                         f"AES — try a shorter message, or see the Symmetric tab."}
    try:
        ct = pub.encrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
    except Exception:
        return {"ok": False, "error": "Encryption failed — check the public key."}
    return {"ok": True, "result": {"ciphertext": b64(ct)},
            "math": [m("Padding", "OAEP with SHA-256 + MGF1"),
                     m("Plaintext size", f"{len(data)} bytes (max {max_bytes})"),
                     m("Ciphertext size", f"{len(ct)} bytes")]}


def rsa_decrypt(private_pem: str, ciphertext_b64: str):
    if not (private_pem or "").strip():
        return {"ok": False,
                "error": "No private key yet — click “Generate keypair” first."}
    if not (ciphertext_b64 or "").strip():
        return {"ok": False,
                "error": "Nothing to decrypt yet — encrypt a message first."}
    try:
        priv = serialization.load_pem_private_key(private_pem.encode(), None)
        pt = priv.decrypt(
            unb64(ciphertext_b64),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
    except Exception:
        return {"ok": False, "error": "Decrypt failed — wrong key or ciphertext."}
    return {"ok": True, "result": {"plaintext": pt.decode("utf-8", "replace")},
            "math": [m("Padding", "OAEP SHA-256")]}


# =========================================================================
# 5. DIGITAL SIGNATURES  (Ed25519 / ECDSA-P256 / RSA-PSS / ML-DSA)
# =========================================================================
def sig_keygen(scheme: str):
    if scheme == "Ed25519":
        sk = ed25519.Ed25519PrivateKey.generate()
        priv = b64(sk.private_bytes(serialization.Encoding.Raw,
                                    serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption()))
        pub = b64(sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        math = [m("Scheme", "Ed25519 (EdDSA on Curve25519)"),
                m("Public key size", "32 bytes"),
                m("Signature size", "64 bytes")]
    elif scheme == "ECDSA-P256":
        sk = ec.generate_private_key(ec.SECP256R1())
        priv = b64(sk.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
        pub = b64(sk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        math = [m("Scheme", "ECDSA over NIST P-256"),
                m("Curve", "secp256r1"),
                m("Security", "elliptic-curve discrete log")]
    elif scheme == "RSA-PSS":
        sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv = b64(sk.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
        pub = b64(sk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        math = [m("Scheme", "RSA-2048 PSS"),
                m("Padding", "PSS with SHA-256")]
    elif scheme == "ML-DSA (Dilithium)":
        pk, sk_raw = ML_DSA_65.keygen()
        priv, pub = b64(sk_raw), b64(pk)
        math = [m("Scheme", "ML-DSA-65 (Dilithium, FIPS 204)"),
                m("Type", "POST-QUANTUM signature"),
                m("Public key size", f"{len(pk)} bytes"),
                m("Security", "hardness of lattice problems (Module-LWE)")]
    else:
        return {"ok": False, "error": f"unknown scheme {scheme}"}
    return {"ok": True,
            "result": {"private_key": priv, "public_key": pub, "scheme": scheme},
            "math": math}


def sig_sign(scheme: str, private_key_b64: str, message: str):
    msg = message.encode("utf-8")
    try:
        if scheme == "Ed25519":
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(unb64(private_key_b64))
            sig = sk.sign(msg)
        elif scheme == "ECDSA-P256":
            sk = serialization.load_pem_private_key(unb64(private_key_b64), None)
            sig = sk.sign(msg, ec.ECDSA(hashes.SHA256()))
        elif scheme == "RSA-PSS":
            sk = serialization.load_pem_private_key(unb64(private_key_b64), None)
            sig = sk.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        elif scheme == "ML-DSA (Dilithium)":
            sig = ML_DSA_65.sign(unb64(private_key_b64), msg)
        else:
            return {"ok": False, "error": "unknown scheme"}
    except Exception as e:
        return {"ok": False, "error": f"Signing failed: {e}"}
    return {"ok": True, "result": {"signature": b64(sig)},
            "math": [m("Scheme", scheme),
                     m("Message digest", hashlib.sha256(msg).hexdigest()),
                     m("Signature size", f"{len(sig)} bytes")]}


def sig_verify(scheme: str, public_key_b64: str, message: str, signature_b64: str):
    msg = message.encode("utf-8")
    sig = unb64(signature_b64)
    try:
        if scheme == "Ed25519":
            pk = ed25519.Ed25519PublicKey.from_public_bytes(unb64(public_key_b64))
            pk.verify(sig, msg)
        elif scheme == "ECDSA-P256":
            pk = serialization.load_pem_public_key(unb64(public_key_b64))
            pk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        elif scheme == "RSA-PSS":
            pk = serialization.load_pem_public_key(unb64(public_key_b64))
            pk.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                      salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        elif scheme == "ML-DSA (Dilithium)":
            if not ML_DSA_65.verify(unb64(public_key_b64), msg, sig):
                raise ValueError("bad signature")
        else:
            return {"ok": False, "error": "unknown scheme"}
    except Exception:
        return {"ok": True, "result": {"valid": False},
                "math": [m("Result", "❌ INVALID — signature does not match")]}
    return {"ok": True, "result": {"valid": True},
            "math": [m("Result", "✅ VALID — authentic and untampered"),
                     m("Scheme", scheme)]}


# =========================================================================
# 6. KEY EXCHANGE  (X25519 ECDH / ML-KEM / Hybrid)  — full demo per call
# =========================================================================
def kex_x25519():
    a = x25519.X25519PrivateKey.generate()
    b = x25519.X25519PrivateKey.generate()
    a_pub, b_pub = a.public_key(), b.public_key()
    a_shared = a.exchange(b_pub)
    b_shared = b.exchange(a_pub)
    rawpub = lambda k: k.public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    return {
        "ok": True,
        "result": {"shared_secret": a_shared.hex(),
                   "match": a_shared == b_shared},
        "math": [
            m("Protocol", "X25519 Elliptic-Curve Diffie–Hellman"),
            m("Alice public", rawpub(a_pub).hex()),
            m("Bob public", rawpub(b_pub).hex()),
            m("Alice computes", "shared = a_priv · B_pub"),
            m("Bob computes", "shared = b_priv · A_pub"),
            m("Secrets equal?", "YES ✅" if a_shared == b_shared else "NO"),
            m("Shared secret", a_shared.hex()),
        ],
    }


def kex_mlkem():
    ek, dk = ML_KEM_768.keygen()          # Bob's (encaps, decaps) keypair
    shared_A, ct = ML_KEM_768.encaps(ek)  # Alice encapsulates
    shared_B = ML_KEM_768.decaps(dk, ct)  # Bob decapsulates
    return {
        "ok": True,
        "result": {"shared_secret": shared_A.hex(),
                   "match": shared_A == shared_B},
        "math": [
            m("Protocol", "ML-KEM-768 (Kyber, FIPS 203)"),
            m("Type", "POST-QUANTUM key encapsulation"),
            m("Encapsulation key (Bob pub)", _short(ek.hex())),
            m("Ciphertext (Alice→Bob)", _short(ct.hex())),
            m("Sizes", f"pub {len(ek)}B · ciphertext {len(ct)}B · secret {len(shared_A)}B"),
            m("Secrets equal?", "YES ✅" if shared_A == shared_B else "NO"),
            m("Shared secret", shared_A.hex()),
            m("Security", "Module-LWE lattice problem (quantum-resistant)"),
        ],
    }


def kex_hybrid():
    # Classical half: X25519
    a = x25519.X25519PrivateKey.generate()
    b = x25519.X25519PrivateKey.generate()
    ec_shared = a.exchange(b.public_key())
    # PQ half: ML-KEM
    ek, dk = ML_KEM_768.keygen()
    pq_shared, ct = ML_KEM_768.encaps(ek)
    # Combine both via HKDF (this is how TLS 1.3 hybrid X25519MLKEM768 works)
    combined = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"CryptX-hybrid-x25519+mlkem768").derive(ec_shared + pq_shared)
    return {
        "ok": True,
        "result": {"shared_secret": combined.hex()},
        "math": [
            m("Protocol", "Hybrid  X25519 + ML-KEM-768"),
            m("Why hybrid", "secure if EITHER classical OR post-quantum holds"),
            m("Classical secret (X25519)", _short(ec_shared.hex())),
            m("Post-quantum secret (ML-KEM)", _short(pq_shared.hex())),
            m("Combiner", "HKDF-SHA256( ecdh ‖ mlkem )"),
            m("Final shared key (256-bit)", combined.hex()),
            m("Used in", "TLS 1.3 today as X25519MLKEM768"),
        ],
    }


# =========================================================================
# 7. ZERO-KNOWLEDGE PROOF  (non-interactive Schnorr, discrete log)
#     Prover shows they know x such that y = g^x  — without revealing x.
# =========================================================================
# RFC 3526 2048-bit safe prime p = 2q+1.  g=4 generates the prime-order-q subgroup.
_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
_Q = (_P - 1) // 2
_G = 4


def zkp_prove_verify(secret: str, tamper: bool = False):
    # Map the secret string to an exponent x in [1, q)
    x = int.from_bytes(hashlib.sha256(secret.encode()).digest(), "big") % _Q or 1
    y = pow(_G, x, _P)                       # public value  y = g^x

    # --- Prover ---
    r = secrets.randbelow(_Q - 1) + 1        # random nonce
    t = pow(_G, r, _P)                       # commitment  t = g^r
    # Fiat–Shamir challenge  c = H(g, y, t)
    c = int.from_bytes(hashlib.sha256(
        f"{_G}|{y}|{t}".encode()).digest(), "big") % _Q
    s = (r + c * x) % _Q                     # response  s = r + c·x  (mod q)

    if tamper:                               # forge without knowing x
        s = (s + 1) % _Q

    # --- Verifier --- checks  g^s == t · y^c  (mod p)
    lhs = pow(_G, s, _P)
    rhs = (t * pow(y, c, _P)) % _P
    valid = lhs == rhs

    return {
        "ok": True,
        "result": {"valid": valid, "secret_revealed": False},
        "math": [
            m("Protocol", "Schnorr NIZK (Fiat–Shamir) — proof of knowledge of x"),
            m("Public statement", "I know x such that  y = g^x mod p"),
            m("Group", "2048-bit safe-prime subgroup, order q"),
            m("Public y = g^x", _short(str(y))),
            m("① commitment  t = g^r", _short(str(t))),
            m("② challenge  c = H(g,y,t)", _short(str(c))),
            m("③ response  s = r + c·x mod q", _short(str(s))),
            m("Verifier checks  g^s == t·y^c", "HOLDS ✅" if valid else "FAILS ❌"),
            m("Secret x transmitted?", "NEVER — that's the zero-knowledge part"),
            m("Note", "tampered response → check fails (soundness)"
                      if tamper else "honest prover → check passes (completeness)"),
        ],
    }


# =========================================================================
# 8. FILE OPERATIONS  (practical utility: integrity + at-rest encryption)
# =========================================================================
_FILE_MAGIC = b"CRYPTX01"


def file_hash(data_b64: str, algo: str, filename: str = "file"):
    """Fingerprint a file so a recipient can verify it arrived unaltered."""
    if algo not in _HASH_ALGOS:
        return {"ok": False, "error": f"unknown algorithm {algo}"}
    data = unb64(data_b64)
    fn, _, out_bits = _HASH_ALGOS[algo]
    digest = fn(data).digest()
    return {
        "ok": True,
        "result": {"hex": digest.hex(), "filename": filename},
        "math": [
            m("File", filename),
            m("Algorithm", algo),
            m("File size", f"{len(data):,} bytes"),
            m("Digest", digest.hex()),
            m("Use", "compare this to the sender's digest — if they match, "
                     "the file is intact and untampered"),
        ],
    }


def file_encrypt(data_b64: str, password: str, filename: str = "file"):
    """Encrypt a file with a password. Output is a self-contained .cryptx blob."""
    data = unb64(data_b64)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = hash_secret_raw(password.encode(), salt, time_cost=3, memory_cost=65536,
                          parallelism=4, hash_len=32, type=Argon2Type.ID)
    name_bytes = filename.encode("utf-8")[:255]
    ct = AESGCM(key).encrypt(nonce, data, None)
    blob = (_FILE_MAGIC + len(name_bytes).to_bytes(1, "big") + name_bytes
            + salt + nonce + ct)
    return {
        "ok": True,
        "result": {"blob_b64": b64(blob), "download_name": filename + ".cryptx"},
        "math": [
            m("File", filename),
            m("Cipher", "AES-256-GCM"),
            m("Key from", "Argon2id(password, random salt)"),
            m("Salt", salt.hex()),
            m("Nonce", nonce.hex()),
            m("Original size", f"{len(data):,} bytes"),
            m("Encrypted size", f"{len(blob):,} bytes"),
            m("Note", "keep the password safe — without it the file cannot be recovered"),
        ],
    }


def file_decrypt(blob_b64: str, password: str):
    """Reverse file_encrypt, recovering the original file and its name."""
    try:
        blob = unb64(blob_b64)
        if blob[:8] != _FILE_MAGIC:
            return {"ok": False, "error": "Not a CryptX file (bad header)."}
        nlen = blob[8]
        i = 9
        name = blob[i:i + nlen].decode("utf-8", "replace"); i += nlen
        salt = blob[i:i + 16]; i += 16
        nonce = blob[i:i + 12]; i += 12
        ct = blob[i:]
        key = hash_secret_raw(password.encode(), salt, time_cost=3, memory_cost=65536,
                              parallelism=4, hash_len=32, type=Argon2Type.ID)
        data = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        return {"ok": False,
                "error": "Could not decrypt — wrong password or the file is corrupted."}
    return {
        "ok": True,
        "result": {"data_b64": b64(data), "download_name": name},
        "math": [
            m("Recovered file", name),
            m("Size", f"{len(data):,} bytes"),
            m("Integrity", "GCM tag verified — file is authentic"),
        ],
    }


INDEX_HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CryptX — a visual guide to cryptography</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --ink:#0e1024; --ink2:#171a35; --panel:#f7f6f2; --panel2:#ecebe4;
  --line:#2a2e52; --line-lt:#dcdbd2;
  --violet:#7c5cff; --violet-dim:#a99bff; --teal:#00c2a8; --amber:#ffb454;
  --rose:#ff5d73; --text:#14162e; --muted:#6b6d82; --muted-lt:#9fa6c9;
  --paper-text:#22243d;
  --mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  --disp:'Space Grotesk',system-ui,sans-serif;
  --body:'Inter',system-ui,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0}
body{
  font-family:var(--body); color:var(--text);
  background:var(--ink);
  background-image:radial-gradient(var(--line) 1px,transparent 1.4px);
  background-size:26px 26px;
  min-height:100vh;
}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 60px;display:grid;
  grid-template-columns:236px 1fr;gap:26px}
/* ---- header ---- */
header{grid-column:1/-1;display:flex;align-items:baseline;gap:16px;
  padding-bottom:14px;border-bottom:1px solid var(--line)}
.logo{font-family:var(--disp);font-weight:700;font-size:30px;letter-spacing:-.5px;
  color:#fff}
.logo b{color:var(--violet-dim)}
.tag{font-family:var(--mono);font-size:12px;color:var(--muted-lt)}
.warn{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--amber);
  border:1px solid #5a4a24;background:#241d10;padding:5px 10px;border-radius:6px}
/* ---- nav ---- */
nav{display:flex;flex-direction:column;gap:3px;position:sticky;top:20px;align-self:start}
.navsec{font-family:var(--mono);font-size:10px;letter-spacing:.6px;text-transform:uppercase;
  color:var(--muted-lt);opacity:.7;margin:14px 12px 4px}
.navsec:first-child{margin-top:2px}
.navbtn{font-family:var(--disp);font-size:14.5px;font-weight:500;text-align:left;line-height:1.3;
  color:var(--muted-lt);background:transparent;border:0;border-left:2px solid transparent;
  padding:9px 12px 10px;cursor:pointer;border-radius:0 6px 6px 0;transition:.15s}
.navbtn:hover{color:#fff;background:#ffffff0d}
.navbtn.active{color:#fff;background:#ffffff14;border-left-color:var(--violet)}
.navbtn small{display:block;font-family:var(--mono);font-size:10px;color:var(--muted-lt);
  font-weight:400;margin-top:2px;line-height:1.5;padding-bottom:1px}
.pq{color:var(--teal)}
/* ---- panels ---- */
main{min-width:0}
.panel{display:none;background:var(--panel);border-radius:14px;padding:30px 32px;
  color:var(--paper-text);box-shadow:0 20px 50px -30px #000}
.panel.active{display:block;animation:rise .25s ease}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.panel h2{font-family:var(--disp);margin:0 0 6px;font-size:26px;letter-spacing:-.5px;line-height:1.2}
.panel .lede{margin:0 0 22px;color:var(--muted);font-size:14.5px;max-width:68ch;line-height:1.65}
.badge{font-family:var(--mono);font-size:10.5px;font-weight:600;padding:2px 7px;
  border-radius:20px;vertical-align:middle;margin-left:8px}
.badge.pq{background:#d5f6f0;color:#046a5b;border:1px solid #9fe4d8}
/* ---- explainer card ---- */
.explain{border:1px solid var(--line-lt);border-radius:12px;overflow:hidden;margin:0 0 22px;
  background:linear-gradient(180deg,#fbfaf6,#f3f1ea)}
.explain summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;
  padding:14px 18px;font-family:var(--disp);font-weight:600;font-size:14.5px;color:var(--paper-text)}
.explain summary::-webkit-details-marker{display:none}
.explain summary .chev{margin-left:auto;transition:.2s;color:var(--muted);font-size:13px}
.explain[open] summary .chev{transform:rotate(90deg)}
.explain summary .pill{font-family:var(--mono);font-size:10px;font-weight:600;color:#4a34c7;
  background:#e7e2ff;border-radius:20px;padding:2px 8px}
.explain .body{padding:2px 16px 18px}
.plain{font-size:14px;line-height:1.7;color:var(--paper-text);margin:0 0 16px;max-width:70ch}
.plain b{color:#4a34c7}
.steps{display:flex;flex-direction:column;gap:8px;margin:0 0 6px}
.stp{display:flex;gap:11px;align-items:flex-start;font-size:13.5px;line-height:1.6;color:var(--paper-text)}
.stp .n{flex:none;width:22px;height:22px;border-radius:50%;background:var(--violet);color:#fff;
  font-family:var(--disp);font-weight:600;font-size:12px;display:grid;place-items:center;margin-top:1px}
.dia{margin:6px 0 4px;background:#fff;border:1px solid var(--line-lt);border-radius:10px;padding:12px}
.dia svg{width:100%;height:auto;display:block}
/* ---- controls ---- */
label.fld{display:block;font-size:11.5px;font-weight:700;color:var(--muted);
  margin:16px 0 6px;text-transform:uppercase;letter-spacing:.6px}
input[type=text],input[type=number],input[type=password],textarea,select{
  width:100%;font-family:var(--mono);font-size:13.5px;color:var(--paper-text);
  background:#fff;border:1px solid var(--line-lt);border-radius:8px;padding:11px 13px;line-height:1.45}
textarea{resize:vertical;min-height:70px;line-height:1.45}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--violet);
  box-shadow:0 0 0 3px #7c5cff22}
.row{display:flex;gap:12px;flex-wrap:wrap}
.row>*{flex:1;min-width:150px}
.btnrow{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
button.go{font-family:var(--disp);font-weight:600;font-size:14px;cursor:pointer;
  color:#fff;background:var(--violet);border:0;padding:10px 18px;border-radius:8px;
  transition:.15s}
button.go:hover{background:#6a49f2;transform:translateY(-1px)}
button.go.ghost{background:transparent;color:var(--violet);border:1px solid var(--violet)}
button.go.ghost:hover{background:#7c5cff12}
button.go.teal{background:var(--teal)}button.go.teal:hover{background:#03ad96}
.chk{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--muted);
  font-family:var(--body);margin-top:14px;cursor:pointer}
.chk input{width:auto}
/* ---- output ---- */
.out{margin-top:22px;display:none}
.out.show{display:block;animation:rise .2s ease}
.result{background:var(--ink);border-radius:10px;padding:14px 16px;color:#eef}
.result .k{font-family:var(--mono);font-size:11px;color:var(--muted-lt);
  text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.slip{font-family:var(--mono);font-size:12.5px;line-height:1.6;word-break:break-all;
  white-space:pre-wrap;color:#dfe3ff;border-left:3px solid var(--violet);padding-left:13px;
  margin:3px 0 14px}
.slip.teal{border-color:var(--teal)}.slip.amber{border-color:var(--amber)}
.copy{float:right;font-family:var(--mono);font-size:11px;color:var(--violet-dim);
  background:#ffffff10;border:1px solid var(--line);border-radius:5px;padding:2px 8px;cursor:pointer}
.copy:hover{background:#ffffff1e}
/* math table */
.math{margin-top:16px;border:1px solid var(--line-lt);border-radius:10px;overflow:hidden}
.math .mh{font-family:var(--disp);font-weight:700;font-size:13px;background:var(--panel2);
  padding:11px 16px;color:var(--paper-text);letter-spacing:.2px}
.math .mr{display:grid;grid-template-columns:210px 1fr;gap:14px;padding:11px 16px;
  border-top:1px solid var(--line-lt);font-size:13px;line-height:1.5}
.math .mr .ml{color:var(--muted);font-weight:500}
.math .mr .mv{font-family:var(--mono);color:var(--paper-text);word-break:break-all}
.verdict{font-family:var(--disp);font-weight:600;font-size:15px;padding:12px 16px;
  border-radius:10px;margin-top:16px}
.verdict.ok{background:#d5f6f0;color:#046a5b}
.verdict.bad{background:#ffe0e4;color:#a01427}
.err{background:#ffe0e4;color:#a01427;font-size:13px;padding:12px 16px;border-radius:10px;
  margin-top:16px;font-family:var(--mono)}
.hint{font-size:12.5px;color:var(--muted);margin-top:10px;line-height:1.6;font-style:italic}
.agrid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:6px}
.acard{border:1px solid var(--line-lt);border-radius:11px;padding:14px 16px;background:#fff;transition:.15s}
.acard.maplink{cursor:pointer}
.acard.maplink:hover{border-color:var(--violet);transform:translateY(-2px);
  box-shadow:0 12px 26px -18px var(--violet)}
.acard b{font-family:var(--disp);font-size:14px;display:block;margin-bottom:3px}
.acard span{font-size:12.5px;color:var(--muted);line-height:1.5}
.note{margin-top:20px;background:#fff6e5;border:1px solid #f0dca8;color:#7a5a12;
  font-size:13px;padding:14px 16px;border-radius:10px;line-height:1.6}
.fcard{border:1px solid var(--line-lt);border-radius:11px;padding:16px 18px;margin-top:14px;background:#fff}
.fcard h3{font-family:var(--disp);margin:0 0 3px;font-size:15px}
.fcard .sub{margin:0 0 10px;color:var(--muted);font-size:12.5px;line-height:1.45}
.fcard input[type=file]{display:block;margin-bottom:9px;font-family:var(--body);font-size:12.5px}
.fcard input[type=text]{margin-bottom:9px}
/* avalanche visualizer */
.bits{display:flex;flex-wrap:wrap;gap:3px;margin-top:10px;font-family:var(--mono);font-size:0}
.bit{width:11px;height:16px;border-radius:2px;background:#e4e3db;display:inline-block}
.bit.on{background:#c8c7bd}
.bit.flip{background:var(--rose);box-shadow:0 0 0 1px #ff5d7355}
.avstat{display:flex;gap:18px;flex-wrap:wrap;margin-top:14px}
.avstat .big{font-family:var(--disp);font-weight:700;font-size:26px;color:var(--violet)}
.avstat .cap{font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
/* learn / map */
.maplink{cursor:pointer}
.branch{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:6px}
.bcard{border:1px solid var(--line-lt);border-radius:12px;padding:14px 16px;cursor:pointer;
  transition:.15s;background:#fff}
.bcard:hover{border-color:var(--violet);transform:translateY(-2px);box-shadow:0 12px 26px -18px #7c5cff}
.bcard .ic{font-size:20px}
.bcard b{font-family:var(--disp);display:block;font-size:15px;margin:6px 0 3px}
.bcard span{font-size:12.5px;color:var(--muted);line-height:1.45}
.bcard .to{font-family:var(--mono);font-size:11px;color:var(--violet);margin-top:8px;display:inline-block}
.glo{border:1px solid var(--line-lt);border-radius:10px;overflow:hidden;margin-top:8px}
.glo .g{display:grid;grid-template-columns:150px 1fr;gap:12px;padding:9px 14px;font-size:13px;
  border-top:1px solid var(--line-lt);line-height:1.45}
.glo .g:first-child{border-top:0}
.glo .g b{font-family:var(--disp);color:var(--paper-text)}
.glo .g span{color:var(--muted)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.sec-h{font-family:var(--disp);font-weight:700;font-size:17px;margin:30px 0 12px;color:var(--paper-text);
  padding-bottom:8px;border-bottom:2px solid var(--line-lt);letter-spacing:-.2px}
/* hero CTA on overview */
.hero{display:grid;grid-template-columns:auto 1fr auto;gap:16px;align-items:center;
  background:linear-gradient(120deg,#efeaff,#e6fbf6);border:1.5px solid #c9bcff;
  border-radius:14px;padding:18px 20px;margin:4px 0 6px;cursor:pointer;transition:.18s}
.hero:hover{transform:translateY(-2px);box-shadow:0 18px 36px -22px var(--violet);
  border-color:var(--violet)}
.hero-ic{font-size:32px;line-height:1}
.hero-tx b{font-family:var(--disp);font-size:16.5px;display:block;margin-bottom:4px;color:#2c1d7a}
.hero-tx span{font-size:13px;color:var(--muted);line-height:1.55;display:block;max-width:62ch}
.hero-go{font-family:var(--disp);font-weight:700;font-size:13.5px;color:#fff;
  background:var(--violet);border-radius:8px;padding:9px 15px;white-space:nowrap}
/* focus visibility for keyboard users */
button.go:focus-visible,.navbtn:focus-visible,.acard.maplink:focus-visible,.bcard:focus-visible{
  outline:2px solid var(--violet);outline-offset:2px}
@media(max-width:820px){.hero{grid-template-columns:auto 1fr;gap:12px}
  .hero-go{grid-column:1/-1;text-align:center}}
/* ===== guided walkthrough stage ===== */
.stage{display:grid;grid-template-columns:120px 1fr 120px;gap:14px;align-items:center;
  background:linear-gradient(180deg,#fbfaf6,#f1efe8);border:1px solid var(--line-lt);
  border-radius:14px;padding:20px 18px;margin:0 0 20px}
.actor{text-align:center;transition:.35s}
.actor .face{font-size:34px;line-height:1;filter:grayscale(.6);transition:.35s}
.actor.lit .face,.actor.win .face{filter:none;transform:scale(1.12)}
.actor .who{font-family:var(--disp);font-weight:700;font-size:15px;margin-top:4px}
.actor .role{font-family:var(--mono);font-size:10px;color:var(--muted)}
.actor.win .who{color:#046a5b}
.keys{display:flex;flex-direction:column;gap:4px;margin-top:8px;align-items:center}
.ktag{font-family:var(--mono);font-size:9.5px;padding:2px 7px;border-radius:20px;
  background:#e8e7e0;color:#9a9a92;border:1px solid var(--line-lt);opacity:.5;transition:.35s}
.ktag.on{opacity:1}
.ktag.pub.on{background:#d5f6f0;color:#046a5b;border-color:#9fe4d8}
.ktag.prv.on{background:#ffe0e4;color:#a01427;border-color:#f5b8c0}
.keys.ghost{visibility:hidden}
.channel{position:relative;height:104px;align-self:center}
.wire{position:absolute;top:38px;left:0;right:0;height:2px;
  background:repeating-linear-gradient(90deg,var(--line-lt) 0 8px,transparent 8px 16px)}
.chan-label{position:absolute;top:2px;width:100%;text-align:center;font-family:var(--mono);
  font-size:10px;color:var(--muted)}
.packet{position:absolute;top:23px;left:50%;transform:translateX(-50%) scale(.6);
  opacity:0;transition:.4s;font-family:var(--mono);font-size:11px;font-weight:600;
  background:#fff;border:1px solid var(--line-lt);border-radius:8px;padding:5px 12px;
  white-space:nowrap;box-shadow:0 6px 16px -10px #000}
.packet.show{opacity:1;transform:translateX(-50%) scale(1)}
.packet.pub{background:#d5f6f0;border-color:#9fe4d8;color:#046a5b}
.packet.locked{background:#efeaff;border-color:#c9bcff;color:#4a34c7}
.packet.open{background:#d5f6f0;border-color:#9fe4d8;color:#046a5b}
.packet.travel{animation:slide 2.4s ease-in-out infinite}
@keyframes slide{0%{left:26%}50%{left:74%}100%{left:26%}}
.eve{position:absolute;top:62px;width:100%;text-align:center;font-size:16px;transition:.35s}
.eve span{font-family:var(--mono);font-size:10px;color:var(--muted);vertical-align:middle}
.eve.dim{opacity:.3}
/* step rail */
.wsteps{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin:0 0 18px}
.wstep{border:1px solid var(--line-lt);border-radius:10px;padding:9px 10px;background:#fff;
  opacity:.5;transition:.3s}
.wstep.done{opacity:1;border-color:#9fe4d8;background:#f3fcfa}
.wstep.now{opacity:1;border-color:var(--violet);background:#f6f3ff;
  box-shadow:0 8px 20px -14px var(--violet)}
.wstep .wnum{width:20px;height:20px;border-radius:50%;background:var(--line-lt);color:#fff;
  font-family:var(--disp);font-weight:700;font-size:11px;display:grid;place-items:center}
.wstep.now .wnum{background:var(--violet)} .wstep.done .wnum{background:var(--teal)}
.wstep .wtxt{margin-top:6px}
.wstep .wtxt b{font-family:var(--disp);font-size:12px;display:block;line-height:1.3;min-height:2.6em}
.wstep .wtxt span{font-family:var(--mono);font-size:9.5px;color:var(--muted);line-height:1.3;display:block;margin-top:2px}
/* walkthrough panel */
.wpanel{border:1px solid var(--line-lt);border-radius:12px;padding:18px 20px;background:#fff;
  min-height:120px}
.wlede{font-size:14px;line-height:1.65;color:var(--paper-text);margin:0 0 14px;max-width:70ch}
.wlede:last-child{margin-bottom:0}
.wlede b{color:#4a34c7}
.wload{font-family:var(--mono);font-size:13px;color:var(--muted);padding:14px 0}
.wload::after{content:'';animation:dots 1.2s steps(4,end) infinite}
@keyframes dots{0%{content:''}25%{content:'.'}50%{content:'..'}75%{content:'...'}}
.keycards{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:6px 0 4px}
.keycard{border-radius:12px;padding:14px 16px;border:1.5px solid}
.keycard.pub{border-color:#9fe4d8;background:#f3fcfa}
.keycard.prv{border-color:#f5b8c0;background:#fff5f6}
.keycard .kh{font-family:var(--disp);font-weight:700;font-size:13px;letter-spacing:.3px}
.keycard.pub .kh{color:#046a5b} .keycard.prv .kh{color:#a01427}
.keycard .kb{font-size:12.5px;line-height:1.55;color:var(--paper-text);margin:7px 0 9px}
.kpem{font-family:var(--mono);font-size:9.5px;color:var(--muted);background:#ffffffcc;
  border:1px solid var(--line-lt);border-radius:6px;padding:7px 9px;margin:0;
  overflow:hidden;white-space:pre-wrap;word-break:break-all;line-height:1.35}
.wcallout{margin-top:14px;background:#f6f3ff;border-left:3px solid var(--violet);
  border-radius:0 10px 10px 0;padding:12px 15px;font-size:13px;line-height:1.6;color:var(--paper-text)}
.wcallout.ok{background:#f3fcfa;border-left-color:var(--teal)}
.wcallout.bad{background:#fff5f6;border-left-color:var(--rose)}
.wcallout b{color:inherit;font-family:var(--disp)}
/* before / after */
.beforeafter{display:grid;grid-template-columns:1fr 44px 1fr;gap:10px;align-items:center;margin-top:14px}
.ba{border:1px solid var(--line-lt);border-radius:10px;padding:11px 13px;min-width:0}
.ba.plain{background:#f3fcfa;border-color:#9fe4d8}
.ba.cipher{background:#f7f6f2}
.ba .bh{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.5px;
  color:var(--muted);margin-bottom:6px}
.ba .bb{font-size:13px;line-height:1.5;word-break:break-word}
.ba .bb.mono{font-family:var(--mono);font-size:10.5px;color:var(--muted);line-height:1.45}
.baarrow{text-align:center;font-size:20px}
.eyecard{border:1.5px solid #f5b8c0;background:#fff5f6;border-radius:10px;padding:12px 14px;margin:6px 0 4px}
.eyecard .eh{font-family:var(--disp);font-weight:700;font-size:13px;color:#a01427;margin-bottom:7px}
.eyecard .eb{font-family:var(--mono);font-size:10.5px;line-height:1.5;word-break:break-all;
  color:var(--muted);max-height:110px;overflow:auto}
.reveal{border:1.5px solid #9fe4d8;background:#f3fcfa;border-radius:10px;padding:14px 16px;margin-top:12px}
.reveal .rh{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#046a5b}
.reveal .rb{font-family:var(--disp);font-size:17px;line-height:1.5;color:#0b3f36;margin-top:6px}
/* generic card used across tabs */
.counter{font-family:var(--mono);font-size:11px;color:var(--muted);text-align:right;margin-top:6px}
.counter .over{color:var(--rose);font-weight:600}
.counter .over::after{content:' \2014 too long for RSA'}
.card{border:1px solid var(--line-lt);border-radius:12px;padding:16px 18px;background:#fff;margin-top:14px}
.card-h{font-family:var(--disp);font-size:15px;margin:0 0 4px}
@media(max-width:820px){
  .stage{grid-template-columns:1fr;gap:10px}
  .channel{height:80px}
  .wsteps{grid-template-columns:repeat(2,1fr)}
  .keycards,.beforeafter{grid-template-columns:1fr}
  .baarrow{transform:rotate(90deg)}
}
@media(max-width:560px){.agrid,.branch,.two,.glo .g{grid-template-columns:1fr}}
@media(max-width:640px){
  header{flex-wrap:wrap;gap:6px 12px}
  .logo{font-size:25px}
  .tag{flex:1 1 100%;order:3;font-size:10.5px}
  .warn{margin-left:0;order:2;font-size:10px;padding:4px 8px}
  .panel{padding:22px 18px}
  .panel h2{font-size:22px}
}
@media(max-width:820px){.wrap{grid-template-columns:1fr}
  nav{flex-direction:row;flex-wrap:wrap;position:static}
  .navsec{width:100%}
  .math .mr{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <span class="logo">Crypt<b>X</b></span>
    <span class="tag">a visual, hands-on guide to cryptography</span>
    <span class="warn">⚠ learning tool — not audited for production secrets</span>
  </header>

  <nav id="nav"></nav>

  <main id="main"></main>
</div>

<script>
// ---------- helpers ----------
const $ = (s,r=document)=>r.querySelector(s);
async function post(url,body){
  const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body||{})});
  return r.json();
}
function copy(t){navigator.clipboard&&navigator.clipboard.writeText(t);}
function download(name,b64,mime){const a=document.createElement('a');
  a.href='data:'+(mime||'application/octet-stream')+';base64,'+b64;a.download=name;
  document.body.appendChild(a);a.click();a.remove();}
function fileToB64(file){return new Promise((res,rej)=>{const r=new FileReader();
  r.onload=()=>res(r.result.split(',')[1]);r.onerror=rej;r.readAsDataURL(file);});}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

function render(box, res, {resultRows=[], mathTitle='Under the hood'}={}){
  if(!res.ok){ box.innerHTML = `<div class="err">${res.error||'Something went wrong.'}</div>`;
    box.classList.add('show'); return; }
  let html = '';
  if(res.result && res.result.valid!==undefined && resultRows.length===0){
    html += `<div class="verdict ${res.result.valid?'ok':'bad'}">${
      res.result.valid?'✅ VALID':'❌ INVALID'}</div>`;
  }
  if(resultRows.length){
    html += '<div class="result">';
    for(const [lbl,val,cls] of resultRows){
      if(val===undefined||val===null) continue;
      html += `<div class="k">${lbl}<button class="copy" data-c="${encodeURIComponent(val)}">copy</button></div>`+
              `<div class="slip ${cls||''}">${esc(val)}</div>`;
    }
    html += '</div>';
  }
  if(res.math && res.math.length){
    html += `<div class="math"><div class="mh">${mathTitle}</div>`;
    for(const row of res.math)
      html += `<div class="mr"><div class="ml">${row.label}</div><div class="mv">${esc(String(row.value))}</div></div>`;
    html += '</div>';
  }
  box.innerHTML = html;
  box.classList.add('show');
  box.querySelectorAll('.copy').forEach(b=>b.onclick=()=>{copy(decodeURIComponent(b.dataset.c||''));b.textContent='copied';setTimeout(()=>b.textContent='copy',900);});
}

// ---------- explainer + diagrams ----------
function EX(plain, steps, kind, {open=true}={}){
  const st = steps.map(s=>`<div class="stp"><div class="n">•</div><div>${s}</div></div>`)
    .map((h,i)=>h.replace('>•<','>'+(i+1)+'<')).join('');
  return `<details class="explain" ${open?'open':''}>
    <summary><span class="pill">HOW IT WORKS</span>
      <span class="chev">▶</span></summary>
    <div class="body">
      <p class="plain">${plain}</p>
      <div class="dia">${DIA[kind]||''}</div>
      <div class="steps">${st}</div>
    </div></details>`;
}

// tiny SVG builders (kept simple + labelled). Palette matches the app.
const C={v:'#7c5cff',t:'#00c2a8',a:'#ffb454',r:'#ff5d73',ink:'#22243d',mut:'#6b6d82',ln:'#c9c8bf'};
function box(x,y,w,h,fill,label,sub){
  return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="9" fill="${fill}" stroke="${C.ln}"/>`+
    `<text x="${x+w/2}" y="${y+(sub?h/2-3:h/2+4)}" text-anchor="middle" font-family="Space Grotesk" font-size="13" font-weight="600" fill="${C.ink}">${label}</text>`+
    (sub?`<text x="${x+w/2}" y="${y+h/2+13}" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${C.mut}">${sub}</text>`:'');
}
function arrow(x1,y,x2,color,label){
  const c=color||C.v;
  return `<line x1="${x1}" y1="${y}" x2="${x2-9}" y2="${y}" stroke="${c}" stroke-width="2"/>`+
    `<path d="M${x2-9},${y-5} L${x2},${y} L${x2-9},${y+5} Z" fill="${c}"/>`+
    (label?`<text x="${(x1+x2)/2}" y="${y-9}" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${c}">${label}</text>`:'');
}
const DIA = {
  hash:`<svg viewBox="0 0 640 150">
    ${box(20,52,150,46,'#eef',' Any input','text · file · anything')}
    ${arrow(170,75,235)}
    ${box(235,44,150,62,'#e7e2ff','Hash function','SHA-256 / SHA-3')}
    ${arrow(385,75,450)}
    ${box(450,52,170,46,'#d5f6f0','Fixed fingerprint','64 hex chars')}
    <path d="M450,120 C360,138 300,138 240,120" fill="none" stroke="${C.r}" stroke-width="2" stroke-dasharray="5 5"/>
    <path d="M247,124 L236,118 L244,111 Z" fill="${C.r}"/>
    <text x="345" y="146" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${C.r}">one-way — can't run it backwards</text>
  </svg>`,
  kdf:`<svg viewBox="0 0 640 158">
    ${box(20,18,170,40,'#ffe9cc',' Weak password','\u201chunter2\u201d')}
    ${box(20,80,170,40,'#eef',' Random salt','different every time')}
    ${arrow(190,38,255,C.a)}${arrow(190,100,255,C.a)}
    ${box(255,40,180,58,'#e7e2ff','Argon2id','slow, memory-hard')}
    ${arrow(435,69,500,C.t)}
    ${box(500,46,120,46,'#d5f6f0','Strong key','32 bytes')}
    <text x="320" y="146" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${C.mut}">slow on purpose \u2014 makes guessing millions of passwords hopeless</text>
  </svg>`,
  sym:`<svg viewBox="0 0 640 150">
    ${box(15,52,120,46,'#eef','Plaintext','\u201cmeet at 8\u201d')}
    ${arrow(135,75,205,C.v,'lock')}
    ${box(205,44,120,62,'#e7e2ff','Encrypt','\uD83D\uDD12 AES-GCM')}
    ${arrow(325,75,395,C.v)}
    ${box(395,52,120,46,'#f2f0ff','Ciphertext','scrambled')}
    ${arrow(515,75,585,C.t,'unlock')}
    ${box(585,52,45,46,'#eef','\uD83D\uDD13','')}
    ${box(255,118,120,26,'#fff3cf','same secret key','')}
    <line x1="265" y1="106" x2="290" y2="118" stroke="${C.a}" stroke-width="2"/>
    <line x1="600" y1="98" x2="360" y2="120" stroke="${C.a}" stroke-width="2" stroke-dasharray="4 4"/>
    <text x="150" y="20" font-family="Space Grotesk" font-size="12" font-weight="600" fill="${C.ink}">One key locks AND unlocks</text>
  </svg>`,
  asym:`<svg viewBox="0 0 640 168">
    <text x="20" y="18" font-family="Space Grotesk" font-size="12" font-weight="600" fill="${C.ink}">Alice sends a secret to Bob</text>
    ${box(15,40,120,44,'#eef','Message','from Alice')}
    ${arrow(135,62,205,C.v)}
    ${box(205,34,130,56,'#e7e2ff','Lock with','Bob\u2019s PUBLIC key')}
    ${arrow(335,62,405,C.v)}
    ${box(405,40,110,44,'#f2f0ff','Ciphertext','')}
    ${arrow(515,62,585,C.t)}
    ${box(430,110,180,50,'#d5f6f0','Unlock with','Bob\u2019s PRIVATE key \uD83D\uDD10')}
    <line x1="560" y1="84" x2="540" y2="110" stroke="${C.t}" stroke-width="2"/>
    <text x="20" y="130" font-family="IBM Plex Mono" font-size="10" fill="${C.mut}">Public key = share freely.</text>
    <text x="20" y="146" font-family="IBM Plex Mono" font-size="10" fill="${C.mut}">Private key = keep secret.</text>
    <text x="20" y="162" font-family="IBM Plex Mono" font-size="10" fill="${C.r}">Two different keys.</text>
  </svg>`,
  sig:`<svg viewBox="0 0 640 168">
    <text x="20" y="18" font-family="Space Grotesk" font-size="12" font-weight="600" fill="${C.ink}">Signing</text>
    ${box(15,30,110,42,'#eef','Message','')}
    ${box(15,80,110,42,'#f6e0ff','PRIVATE key','signer only')}
    ${arrow(125,51,190,C.v)}${arrow(125,101,190,C.v)}
    ${box(190,44,120,56,'#e7e2ff','Sign','')}
    ${arrow(310,72,375,C.t)}
    ${box(375,50,120,42,'#d5f6f0','Signature','')}
    <text x="20" y="150" font-family="Space Grotesk" font-size="12" font-weight="600" fill="${C.ink}">Verifying</text>
    <text x="120" y="150" font-family="IBM Plex Mono" font-size="10" fill="${C.mut}">message + signature + PUBLIC key  \u2192  \u2714 genuine  /  \u2718 tampered</text>
  </svg>`,
  kex:`<svg viewBox="0 0 640 192">
    ${box(20,30,120,44,'#e7e2ff','Alice','')}
    ${box(500,30,120,44,'#d5f6f0','Bob','')}
    <text x="320" y="24" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${C.mut}">open channel (anyone can watch)</text>
    ${arrow(140,46,500,C.v,'Alice\u2019s public value \u2192')}
    <line x1="500" y1="62" x2="149" y2="62" stroke="${C.t}" stroke-width="2"/>
    <path d="M149,57 L140,62 L149,67 Z" fill="${C.t}"/>
    <text x="320" y="80" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${C.t}">\u2190 Bob\u2019s public value</text>
    ${box(20,98,120,44,'#fff3cf','shared secret','')}
    ${box(500,98,120,44,'#fff3cf','shared secret','')}
    <text x="320" y="125" text-anchor="middle" font-family="Space Grotesk" font-size="12" font-weight="600" fill="${C.ink}">identical \uD83E\uDD1D</text>
    ${box(240,152,160,34,'#ffe0e4','\uD83D\uDC41 eavesdropper','can\u2019t compute it')}
  </svg>`,
  zkp:`<svg viewBox="0 0 640 176">
    <text x="320" y="16" text-anchor="middle" font-family="Space Grotesk" font-size="12" font-weight="600" fill="${C.ink}">Prove you know it \u2014 without showing it</text>
    ${box(20,40,150,74,'#e7e2ff','Prover','knows secret x')}
    ${box(470,40,150,74,'#d5f6f0','Verifier','wants proof')}
    <text x="320" y="56" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${C.v}">1. commitment \u2192</text>
    <line x1="170" y1="63" x2="461" y2="63" stroke="${C.v}" stroke-width="2"/>
    <path d="M461,58 L470,63 L461,68 Z" fill="${C.v}"/>
    <text x="320" y="79" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${C.a}">\u2190 2. random challenge</text>
    <line x1="470" y1="86" x2="179" y2="86" stroke="${C.a}" stroke-width="2"/>
    <path d="M179,81 L170,86 L179,91 Z" fill="${C.a}"/>
    <text x="320" y="102" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${C.t}">3. response \u2192</text>
    <line x1="170" y1="109" x2="461" y2="109" stroke="${C.t}" stroke-width="2"/>
    <path d="M461,104 L470,109 L461,114 Z" fill="${C.t}"/>
    ${box(230,132,180,30,'#fff3cf','secret x never sent','')}
  </svg>`,
  file:`<svg viewBox="0 0 640 128">
    ${box(20,40,120,46,'#eef','Your file','photo, pdf\u2026')}
    ${box(20,92,120,28,'#fff3cf','password','')}
    ${arrow(140,63,210,C.v)}<line x1="80" y1="92" x2="150" y2="70" stroke="${C.a}" stroke-width="2"/>
    ${box(210,40,150,46,'#e7e2ff','AES-256-GCM','locks the bytes')}
    ${arrow(360,63,430,C.t)}
    ${box(430,40,190,46,'#d5f6f0','.cryptx file','safe to store or send')}
    <text x="320" y="120" text-anchor="middle" font-family="IBM Plex Mono" font-size="10" fill="${C.mut}">no password \u2192 the file is just noise</text>
  </svg>`,
  symasym:`<svg viewBox="0 0 640 200">
    <rect x="8" y="8" width="300" height="184" rx="12" fill="#f3f1fb" stroke="${C.ln}"/>
    <rect x="332" y="8" width="300" height="184" rx="12" fill="#eef7f5" stroke="${C.ln}"/>
    <text x="158" y="34" text-anchor="middle" font-family="Space Grotesk" font-size="14" font-weight="700" fill="${C.v}">Symmetric</text>
    <text x="482" y="34" text-anchor="middle" font-family="Space Grotesk" font-size="14" font-weight="700" fill="${C.t}">Asymmetric</text>
    ${box(48,54,220,34,'#fff','ONE shared key','')}
    <text x="158" y="112" text-anchor="middle" font-family="IBM Plex Mono" font-size="11" fill="${C.mut}">locks + unlocks</text>
    <text x="158" y="134" text-anchor="middle" font-family="IBM Plex Mono" font-size="11" fill="${C.mut}">very fast</text>
    <text x="158" y="160" text-anchor="middle" font-family="IBM Plex Mono" font-size="10.5" fill="${C.ink}">problem: how do you</text>
    <text x="158" y="175" text-anchor="middle" font-family="IBM Plex Mono" font-size="10.5" fill="${C.ink}">share the key safely?</text>
    ${box(360,54,110,34,'#fff','PUBLIC','locks')}
    ${box(492,54,110,34,'#fff','PRIVATE','unlocks')}
    <text x="482" y="112" text-anchor="middle" font-family="IBM Plex Mono" font-size="11" fill="${C.mut}">two linked keys</text>
    <text x="482" y="134" text-anchor="middle" font-family="IBM Plex Mono" font-size="11" fill="${C.mut}">slower</text>
    <text x="482" y="160" text-anchor="middle" font-family="IBM Plex Mono" font-size="10.5" fill="${C.ink}">solves key sharing +</text>
    <text x="482" y="175" text-anchor="middle" font-family="IBM Plex Mono" font-size="10.5" fill="${C.ink}">enables signatures</text>
  </svg>`,
};

// ---------- tool definitions ----------
const TOOLS = [
 {id:'about', name:'Overview',      sub:'start here',            build:aboutTool, sec:'Start'},
 {id:'learn', name:'Crypto 101',    sub:'the big picture',       build:learnTool, sec:'Start'},
 {id:'walk',  name:'Send a Secret', sub:'guided walkthrough',    build:walkTool,  sec:'Start'},
 {id:'hash',  name:'Hashing',       sub:'fingerprints',          build:hashTool,  sec:'Toolkit'},
 {id:'kdf',   name:'Key Derivation',sub:'password → real key',   build:kdfTool,   sec:'Toolkit'},
 {id:'aes',   name:'Symmetric',     sub:'AES-256-GCM',           build:aesTool,   sec:'Toolkit'},
 {id:'files', name:'File tools',    sub:'encrypt · verify files',build:filesTool, sec:'Toolkit'},
 {id:'rsa',   name:'RSA',           sub:'the raw tool',          build:rsaTool,   sec:'Public key'},
 {id:'sig',   name:'Signatures',    sub:'Ed25519 · PQC',         build:sigTool,   sec:'Public key'},
 {id:'kex',   name:'Key Exchange',  sub:'X25519 · ML-KEM',       build:kexTool,   sec:'Public key'},
 {id:'zkp',   name:'Zero-Knowledge',sub:'Schnorr proof',         build:zkpTool,   sec:'Public key'},
];

function outBox(){return `<div class="out"></div>`;}

// ---- OVERVIEW ----
function aboutTool(){
  return `<h2>Welcome to CryptX</h2>
  <p class="lede">A hands-on, visual guide to how modern cryptography actually works. Every tool
   pairs a plain-English explainer and a diagram with a real, working demo \u2014 and shows you the
   numbers underneath. Poke at it, break it, watch what changes.</p>

  <div class="hero" data-go="walk">
    <div class="hero-ic">\uD83D\uDD10</div>
    <div class="hero-tx">
      <b>Start here: Send a Secret</b>
      <span>A five-step guided walkthrough where you watch a real encrypted message travel from
       Alice to Bob \u2014 past an eavesdropper who can\u2019t read a thing.</span>
    </div>
    <div class="hero-go">Begin \u2192</div>
  </div>

  <div class="sec-h">Explore the toolkit</div>
  <div class="agrid">
    <div class="acard maplink" data-go="learn"><b>\uD83D\uDDFA\uFE0F Crypto 101</b><span>The whole field on one page, in simple language and pictures.</span></div>
    <div class="acard maplink" data-go="hash"><b>\uD83D\uDD2C The avalanche effect</b><span>Change one letter, watch half the fingerprint flip.</span></div>
    <div class="acard maplink" data-go="files"><b>\uD83D\uDD12 Encrypt a real file</b><span>Password-lock any photo or document with AES-256-GCM.</span></div>
    <div class="acard maplink" data-go="kdf"><b>\uD83D\uDD11 Password \u2192 real key</b><span>See how a KDF stretches a weak password, and why salt matters.</span></div>
    <div class="acard maplink" data-go="rsa"><b>\uD83D\uDDDD\uFE0F The raw RSA tool</b><span>Generate keys and drive encryption and decryption yourself.</span></div>
    <div class="acard maplink" data-go="sig"><b>\u270D\uFE0F Sign &amp; tamper-check</b><span>Edit a signed message and watch verification fail instantly.</span></div>
  </div>

  <p class="hint" style="margin-top:16px">Every section opens with a <b>\u201cHow it works\u201d</b> card \u2014
   read the plain-English version and the diagram, then try the tool underneath.</p>
  <div class="note"><b>Good to know:</b> CryptX runs entirely on your own computer and is built for
   learning and personal, local use. It\u2019s great for understanding cryptography and for quick
   local encryption \u2014 but it isn\u2019t a hardened online service, so don\u2019t rely on it to guard
   high-stakes secrets across a network.</div>`;
}

// ---- CRYPTO 101 (the guide) ----
function learnTool(){
  return `<h2>Crypto 101 — the big picture</h2>
  <p class="lede">Cryptography answers four everyday questions about a message. Each one has its
   own tool. Tap any card to jump straight to a live demo.</p>

  <div class="branch">
    <div class="bcard" data-go="aes"><div class="ic">🔒</div><b>Keep it secret</b>
      <span>Scramble a message so only the right person can read it.</span>
      <span class="to">→ Symmetric &amp; RSA</span></div>
    <div class="bcard" data-go="hash"><div class="ic">🧾</div><b>Prove it wasn’t changed</b>
      <span>A tiny fingerprint that changes completely if one bit is altered.</span>
      <span class="to">→ Hashing</span></div>
    <div class="bcard" data-go="sig"><div class="ic">✍️</div><b>Prove who sent it</b>
      <span>A signature only the real sender could produce.</span>
      <span class="to">→ Signatures</span></div>
    <div class="bcard" data-go="kex"><div class="ic">🤝</div><b>Agree on a key</b>
      <span>Two strangers create a shared secret over an open line.</span>
      <span class="to">→ Key Exchange</span></div>
  </div>

  <div class="sec-h">The one idea that unlocks everything: two kinds of keys</div>
  <p class="plain" style="max-width:66ch">Almost all confusion about cryptography clears up once
   you see the difference between <b>symmetric</b> (one shared key) and <b>asymmetric</b>
   (a public + private pair). Here they are side by side.</p>
  <div class="dia">${DIA.symasym}</div>

  <div class="sec-h">Words you’ll keep seeing</div>
  <div class="glo">
    <div class="g"><b>Plaintext</b><span>the readable message before it’s locked.</span></div>
    <div class="g"><b>Ciphertext</b><span>the scrambled version — useless without the key.</span></div>
    <div class="g"><b>Key</b><span>the secret that locks or unlocks. Long &amp; random = strong.</span></div>
    <div class="g"><b>Public / private key</b><span>a linked pair: share one, hide the other.</span></div>
    <div class="g"><b>Hash</b><span>a fixed-size fingerprint of any data. One-way.</span></div>
    <div class="g"><b>Salt</b><span>random bytes added before hashing a password so identical passwords look different.</span></div>
    <div class="g"><b>Nonce / IV</b><span>a “number used once” so encrypting the same thing twice looks different.</span></div>
    <div class="g"><b>Signature</b><span>proof of authorship + integrity, made with a private key.</span></div>
  </div>

  <div class="note" style="margin-top:22px"><b>Reading order that works well:</b> Send a Secret →
   Hashing → Key Derivation → Symmetric → File tools → RSA → Signatures → Key Exchange →
   Zero-Knowledge. Each one builds on the last.</div>`;
}

// ---- HASH (+ avalanche visualizer) ----
function hashTool(){
  return `<h2>Hashing — digital fingerprints</h2>
  <p class="lede">A hash is a one-way fingerprint of any input: same input always gives the same
   fixed-length output, but you can’t work backwards to the input.</p>
  ${EX(`Think of a hash as a <b>blender for data</b>. Put anything in — a word, a whole movie —
    and you always get a fixed-size smoothie out. The same input makes the same smoothie every
    time, but you can never un-blend it back into the original. Change even one letter and you
    get a <b>totally different</b> smoothie — that sensitivity is called the <b>avalanche effect</b>.`,
    [`You feed in any message or file.`,
     `The hash function mixes it thoroughly into a fixed number of bits.`,
     `Out comes a fingerprint — e.g. 64 hex characters for SHA-256.`,
     `Re-hash later and compare: same fingerprint means nothing changed.`],
    'hash')}
  <label class="fld">Message</label>
  <textarea id="h-text">The quick brown fox</textarea>
  <label class="fld">Algorithm</label>
  <select id="h-algo">
    <option>SHA-256</option><option>SHA-384</option><option>SHA-512</option>
    <option>SHA3-256</option><option>SHA3-512</option><option>BLAKE2b</option>
  </select>
  <div class="btnrow"><button class="go" id="h-go">Compute digest</button></div>
  ${outBox()}

  <div class="sec-h">🔬 See the avalanche effect</div>
  <p class="plain">Type in the box, then change a single character and watch how much of the
   fingerprint turns red. Tiny change in, huge change out.</p>
  <label class="fld">Try changing one letter</label>
  <input type="text" id="av-text" value="hello world">
  <div id="av-view"></div>`;
}
function hashInit(){
  $('#h-go').onclick=async()=>{
    const res=await post('/api/hash',{text:$('#h-text').value,algo:$('#h-algo').value});
    render($('.out'),res,{resultRows:[['Digest (hex)',res.result?.hex],
      ['Digest (base64)',res.result?.base64,'teal']]});
  };
  // avalanche
  let base=null, baseText=null;
  async function sha(t){const r=await post('/api/hash',{text:t,algo:'SHA-256'});return r.ok?r.result.hex:null;}
  function bitsOf(hex){const out=[];for(const ch of hex){const v=parseInt(ch,16);
    for(let i=3;i>=0;i--)out.push((v>>i)&1);}return out;}
  async function draw(){
    const t=$('#av-text').value;
    const cur=await sha(t); if(!cur)return;
    if(base===null){base=cur;baseText=t;}
    const a=bitsOf(base), b=bitsOf(cur);
    let flipped=0;
    let cells=b.map((bit,i)=>{const f=bit!==a[i]; if(f)flipped++;
      return `<span class="bit ${bit?'on':''} ${f?'flip':''}"></span>`;}).join('');
    const pct=(flipped/b.length*100).toFixed(1);
    $('#av-view').innerHTML=`<div class="bits">${cells}</div>
      <div class="avstat">
        <div><div class="big">${pct}%</div><div class="cap">of bits flipped</div></div>
        <div><div class="big">${flipped}<span style="font-size:15px;color:#9fa6c9">/256</span></div><div class="cap">bits changed vs baseline</div></div>
      </div>
      <p class="hint">Baseline = “${esc(baseText)}”. Around 50% is ideal — it means the output
       reveals nothing about how close your input was.</p>`;
  }
  $('#av-text').oninput=draw;
  draw();
}

// ---- KEY DERIVATION ----
function kdfTool(){
  return `<h2>Key derivation</h2>
  <p class="lede">A password is short, memorable and predictable. An encryption key needs to be
   long and random. A <b>key derivation function</b> is the bridge between the two.</p>
  ${EX(`You can\u2019t hand a password straight to AES \u2014 it\u2019s the wrong shape and far too easy to
    guess. A KDF <b>stretches</b> it into a proper key: it mixes in random <b>salt</b> so two people
    with the same password get different keys, then deliberately grinds through a lot of slow,
    memory-hungry work. That slowness is the whole point \u2014 it costs you a fraction of a second,
    but it costs an attacker trying billions of guesses a small fortune.`,
    [`You supply a password, and a fresh random <b>salt</b> is generated.`,
     `Argon2id (or PBKDF2 / HKDF) chews on both, slowly and on purpose.`,
     `Out comes a fixed-length key \u2014 32 bytes is a full AES-256 key.`,
     `The salt is stored alongside the ciphertext; it is not a secret.`],
    'kdf')}
  <div class="card">
    <h3 class="card-h">Derive a key from a password</h3>
    <label class="fld">Password</label>
    <input type="text" id="k-pw" value="correct horse battery staple">
    <div class="row">
      <div><label class="fld">Function</label>
        <select id="k-algo"><option>Argon2id</option><option>PBKDF2</option><option>HKDF</option></select></div>
      <div><label class="fld">Output bytes</label><input type="number" id="k-len" value="32" min="16" max="64"></div>
    </div>
    <div class="btnrow"><button class="go" id="k-go">Derive key</button></div>
  </div>
  <p class="hint">Run it twice with the same password \u2014 the key changes every time, because the
   salt does. That is exactly what stops precomputed \u201crainbow table\u201d attacks.</p>
  ${outBox()}`;
}
function kdfInit(){
  $('#k-go').onclick=async()=>{
    const res=await post('/api/kdf',{password:$('#k-pw').value,algo:$('#k-algo').value,length:$('#k-len').value});
    render($('.out'),res,{resultRows:[['Derived key',res.result?.key_hex],
      ['Random salt used',res.result?.salt_hex,'amber']]});
  };
}

// ---- SYMMETRIC ----
function aesTool(){
  return `<h2>Symmetric encryption <span class="badge" style="background:#e7e2ff;color:#4a34c7">AES-256-GCM</span></h2>
  <p class="lede">One shared password both encrypts and decrypts. GCM also authenticates — any
   tampering makes decryption fail rather than return garbage.</p>
  ${EX(`Symmetric encryption is a <b>lockbox with one key</b>. Whoever holds that key can put
    things in and take things out. It’s fast and simple — the only hard part is getting that
    single key to the other person without anyone intercepting it.`,
    [`You pick a password; a salt + key are derived from it.`,
     `AES-256-GCM scrambles your text into ciphertext.`,
     `It also adds an <b>authentication tag</b> — a tamper seal.`,
     `The same password unlocks it; a wrong password or altered byte just fails.`],
    'sym')}
  <label class="fld">Password</label><input type="text" id="a-pw" value="hunter2">
  <label class="fld">Plaintext to encrypt</label><textarea id="a-pt">meet me at dawn</textarea>
  <div class="btnrow"><button class="go" id="a-enc">Encrypt →</button></div>
  <label class="fld" style="margin-top:22px">Encrypted package (paste to decrypt)</label>
  <textarea id="a-pkg" placeholder="base64 package from encrypt…"></textarea>
  <div class="btnrow"><button class="go teal" id="a-dec">← Decrypt</button></div>
  ${outBox()}`;
}
function aesInit(){
  $('#a-enc').onclick=async()=>{
    const res=await post('/api/aes/encrypt',{plaintext:$('#a-pt').value,password:$('#a-pw').value});
    if(res.ok) $('#a-pkg').value=res.result.package;
    render($('.out'),res,{resultRows:[['Encrypted package (self-contained)',res.result?.package,'teal']]});
  };
  $('#a-dec').onclick=async()=>{
    const res=await post('/api/aes/decrypt',{package:$('#a-pkg').value,password:$('#a-pw').value});
    render($('.out'),res,{resultRows:[['Recovered plaintext',res.result?.plaintext,'teal']]});
  };
}

// ---- FILE TOOLS ----
function filesTool(){
  return `<h2>File tools <span class="badge" style="background:#e7e2ff;color:#4a34c7">practical</span></h2>
  <p class="lede">Work with real files: fingerprint one to check it hasn’t changed, or password-lock
   it so only someone with the password can open it.</p>
  ${EX(`Same ideas as before, applied to whole files. <b>Fingerprinting</b> a file lets anyone
    check later that not a single byte changed. <b>Encrypting</b> a file wraps its bytes in
    AES-256-GCM so that, without the password, the download is just noise.`,
    [`Fingerprint: pick a file, get its checksum, share it alongside the file.`,
     `The receiver re-computes it — matching = untouched.`,
     `Encrypt: choose a file + password, download a <b>.cryptx</b> file.`,
     `Decrypt: feed that .cryptx back with the password to get the original.`],
    'file')}
  <div class="fcard">
    <h3>Verify a file</h3>
    <p class="sub">Get a file’s unique fingerprint (checksum). Share it with the file; the
     receiver re-checks it — matching fingerprints mean nothing was altered.</p>
    <input type="file" id="fh-file">
    <select id="fh-algo"><option>SHA-256</option><option>SHA-512</option><option>BLAKE2b</option></select>
    <div class="btnrow"><button class="go" id="fh-go">Fingerprint file</button></div>
  </div>
  <div class="fcard">
    <h3>Encrypt a file</h3>
    <p class="sub">Password-lock any file. You’ll download a <b>.cryptx</b> file that’s safe to store or send.</p>
    <input type="file" id="fe-file">
    <input type="text" id="fe-pw" placeholder="choose a password">
    <div class="btnrow"><button class="go" id="fe-go">Encrypt &amp; download</button></div>
  </div>
  <div class="fcard">
    <h3>Decrypt a .cryptx file</h3>
    <p class="sub">Unlock a file that was encrypted here, using its password.</p>
    <input type="file" id="fd-file">
    <input type="text" id="fd-pw" placeholder="password">
    <div class="btnrow"><button class="go teal" id="fd-go">Decrypt &amp; download</button></div>
  </div>
  ${outBox()}`;
}
function filesInit(){
  $('#fh-go').onclick=async()=>{
    const f=$('#fh-file').files[0]; if(!f)return alert('Choose a file first.');
    const res=await post('/api/file/hash',{data:await fileToB64(f),algo:$('#fh-algo').value,filename:f.name});
    render($('.out'),res,{resultRows:[[$('#fh-algo').value+' fingerprint',res.result?.hex,'teal']]});
  };
  $('#fe-go').onclick=async()=>{
    const f=$('#fe-file').files[0]; if(!f)return alert('Choose a file first.');
    if(!$('#fe-pw').value)return alert('Enter a password.');
    const res=await post('/api/file/encrypt',{data:await fileToB64(f),password:$('#fe-pw').value,filename:f.name});
    if(res.ok)download(res.result.download_name,res.result.blob_b64);
    render($('.out'),res,{});
  };
  $('#fd-go').onclick=async()=>{
    const f=$('#fd-file').files[0]; if(!f)return alert('Choose a .cryptx file first.');
    const res=await post('/api/file/decrypt',{blob:await fileToB64(f),password:$('#fd-pw').value});
    if(res.ok)download(res.result.download_name,res.result.data_b64);
    render($('.out'),res,{});
  };
}

// ---- GUIDED WALKTHROUGH: SEND A SECRET ----
function walkTool(){
  return `<h2>Send a secret</h2>
  <p class="lede">The single most important idea in modern cryptography, done step by step with
   <b>real RSA keys</b>. Alice wants to send Bob a private message. They have never met and share
   no password. Follow along and watch it actually work.</p>

  <div class="stage">
    <div class="actor" id="w-alice">
      <div class="face">👩</div><div class="who">Alice</div><div class="role">the sender</div>
      <div class="keys ghost"><span class="ktag">●</span></div>
    </div>
    <div class="channel">
      <div class="wire"></div>
      <div class="packet" id="w-packet"><span id="w-packet-txt">…</span></div>
      <div class="eve" id="w-eve">🕵️ <span>eavesdropper</span></div>
      <div class="chan-label">the open internet — anyone can watch</div>
    </div>
    <div class="actor" id="w-bob">
      <div class="face">🧔</div><div class="who">Bob</div><div class="role">the recipient</div>
      <div class="keys">
        <span class="ktag pub" id="w-kpub">🔓 public</span>
        <span class="ktag prv" id="w-kprv">🔑 private</span>
      </div>
    </div>
  </div>

  <div class="wsteps" id="w-steps"></div>

  <div class="wpanel" id="w-panel"></div>

  <div class="btnrow">
    <button class="go ghost" id="w-back">← Back</button>
    <button class="go" id="w-next">Start →</button>
    <button class="go ghost" id="w-reset">Reset</button>
  </div>
  <div class="out" id="w-out"></div>`;
}

const W_STEPS = [
  {t:'Bob makes a keypair',      s:'Two linked keys are born'},
  {t:'Bob shares the public key',s:'The lock goes public'},
  {t:'Alice writes + encrypts',  s:'Locked with Bob’s public key'},
  {t:'It crosses the internet',  s:'Eve sees only noise'},
  {t:'Bob decrypts',             s:'Only the private key opens it'},
];

function walkInit(){
  let step = 0;
  const S = {pub:null, priv:null, msg:'', ct:'', wrongPriv:null};

  const stepsBox = $('#w-steps'), panel = $('#w-panel'), out = $('#w-out');
  const packet = $('#w-packet'), pktTxt = $('#w-packet-txt');

  function drawSteps(){
    stepsBox.innerHTML = W_STEPS.map((s,i)=>{
      const st = i < step ? 'done' : (i === step-1 ? 'now' : '');
      return `<div class="wstep ${i<step?'done':''} ${i===step-1?'now':''}">
        <div class="wnum">${i<step?'✓':i+1}</div>
        <div class="wtxt"><b>${s.t}</b><span>${s.s}</span></div>
      </div>`;
    }).join('');
  }

  function needEncrypt(){
    return `<div class="wcallout bad"><b>Nothing to send yet.</b> The rest of the story
      needs a real ciphertext to follow \u2014 go back to <b>step 3</b> and encrypt a
      message first.</div>
      <div class="btnrow"><button class="go ghost" id="w-goback3">\u2190 Back to step 3</button></div>`;
  }
  function setPacket(text, cls){
    pktTxt.textContent = text;
    packet.className = 'packet show ' + (cls||'');
  }

  async function go(){
    step++;
    $('#w-next').textContent = step >= W_STEPS.length ? 'Finish' : 'Next step →';
    $('#w-back').style.visibility = step > 1 ? 'visible' : 'hidden';
    drawSteps();
    out.classList.remove('show');
    setTimeout(()=>{const gb=$('#w-goback3'); if(gb) gb.onclick=()=>$('#w-back').click();},0);

    if(step === 1){
      panel.innerHTML = `<div class="wload">Generating a real 2048-bit RSA keypair for Bob…</div>`;
      const res = await post('/api/rsa/keygen',{bits:2048});
      if(!res.ok){ panel.innerHTML = `<div class="err">${res.error}</div>`; return; }
      S.pub = res.result.public_pem; S.priv = res.result.private_pem;
      $('#w-bob').classList.add('lit');
      $('#w-kpub').classList.add('on'); $('#w-kprv').classList.add('on');
      panel.innerHTML = `
        <p class="wlede">Bob runs one command and gets <b>two mathematically linked keys</b>.
         They are a matched pair: whatever one locks, only the other can open.</p>
        <div class="keycards">
          <div class="keycard pub">
            <div class="kh">🔓 PUBLIC KEY</div>
            <div class="kb">Safe to publish anywhere — on a website, in an email signature, on a
             business card. It can only <b>lock</b> things.</div>
            <pre class="kpem">${esc(S.pub.trim().split('\n').slice(0,3).join('\n'))}…</pre>
          </div>
          <div class="keycard prv">
            <div class="kh">🔑 PRIVATE KEY</div>
            <div class="kb">Never leaves Bob's computer. It is the only thing in the universe that
             can <b>unlock</b> what the public key locked.</div>
            <pre class="kpem">${esc(S.priv.trim().split('\n').slice(0,3).join('\n'))}…</pre>
          </div>
        </div>`;
    }

    if(step === 2){
      setPacket('🔓 Bob\u2019s public key', 'pub');
      panel.innerHTML = `
        <p class="wlede">Bob sends his <b>public</b> key to Alice — over plain email, a tweet,
         anything. This is the part that surprises people: <b>it does not matter who sees it.</b></p>
        <div class="wcallout ok">
          <b>Why is this safe?</b> The public key can only lock. Even if Eve copies it, all she can
          do is create messages that only Bob can read. She cannot use it to open anything.
        </div>
        <p class="wlede">Notice what has <em>not</em> happened: Alice and Bob never agreed on a
         shared password, and never met. That is the whole breakthrough.</p>`;
    }

    if(step === 3){
      panel.innerHTML = `
        <p class="wlede">Now Alice writes her message and locks it with <b>Bob's public key</b>.
         Type anything you like:</p>
        <label class="fld">Alice's secret message</label>
        <textarea id="w-msg">Bob — the meeting moved to 9pm. Come alone.</textarea>
        <div class="counter"><span id="w-count"></span></div>
        <div class="btnrow"><button class="go" id="w-enc">🔒 Encrypt with Bob's public key</button></div>
        <div id="w-encout"></div>`;
      const ta=$('#w-msg'), cnt=$('#w-count');
      const tally=()=>{const n=new Blob([ta.value]).size;
        cnt.textContent=n+' / 190 bytes';
        cnt.className = n>190 ? 'over' : '';};
      ta.oninput=tally; tally();
      $('#w-enc').onclick = async ()=>{
        S.msg = $('#w-msg').value;
        const res = await post('/api/rsa/encrypt',{public_pem:S.pub, plaintext:S.msg});
        if(!res.ok){ $('#w-encout').innerHTML = `<div class="err">${res.error}</div>`; return; }
        S.ct = res.result.ciphertext;
        $('#w-alice').classList.add('lit');
        setPacket('🔒 encrypted', 'locked');
        $('#w-encout').innerHTML = `
          <div class="beforeafter">
            <div class="ba plain"><div class="bh">What Alice wrote</div>
              <div class="bb">${esc(S.msg)}</div></div>
            <div class="baarrow">🔒</div>
            <div class="ba cipher"><div class="bh">What actually gets sent</div>
              <div class="bb mono">${esc(S.ct.slice(0,180))}…</div></div>
          </div>
          <div class="wcallout">Same message, now unreadable. Only Bob's private key can reverse this.</div>`;
        render(out, res, {resultRows:[]});
      };
    }

    if(step === 4){
      if(!S.ct){ panel.innerHTML = needEncrypt(); return; }
      packet.classList.add('travel');
      panel.innerHTML = `
        <p class="wlede">The encrypted message travels across the internet. Let's see exactly what
         an eavesdropper gets.</p>
        <div class="eyecard">
          <div class="eh">🕵️ What Eve intercepts</div>
          <div class="eb mono">${esc(S.ct || '(encrypt a message first)')}</div>
        </div>
        <p class="wlede">Eve has the ciphertext. She also has Bob's public key — remember, it was
         published openly. Let her try to open it with it:</p>
        <div class="btnrow"><button class="go ghost" id="w-eve-try">🕵️ Try to open it with the public key</button>
        <button class="go ghost" id="w-eve-try2">🕵️ Try a different private key</button></div>
        <div id="w-eveout"></div>`;
      $('#w-eve-try').onclick = ()=>{
        $('#w-eveout').innerHTML = `<div class="verdict bad">❌ Impossible — the public key has no unlocking power at all</div>
          <div class="wcallout bad">RSA is <b>asymmetric</b>: the maths only runs one way. The public
           key is built to lock. There is no "reverse" button hiding in it — decryption requires a
           completely different number that Bob never shared.</div>`;
      };
      $('#w-eve-try2').onclick = async ()=>{
        $('#w-eveout').innerHTML = `<div class="wload">Eve generates her own keypair and tries her private key…</div>`;
        const k = await post('/api/rsa/keygen',{bits:2048});
        const res = await post('/api/rsa/decrypt',{private_pem:k.result.private_pem, ciphertext:S.ct});
        $('#w-eveout').innerHTML = `<div class="verdict bad">❌ Failed — wrong private key</div>
          <div class="wcallout bad">Eve's key is a perfectly valid RSA key. It just isn't <b>the</b>
           key. Only the private key that was born alongside Bob's public key can undo this, and
           finding it would mean factoring a 617-digit number.</div>`;
      };
    }

    if(step === 5){
      if(!S.ct){ panel.innerHTML = needEncrypt(); return; }
      packet.classList.remove('travel');
      $('#w-eve').classList.add('dim');
      panel.innerHTML = `
        <p class="wlede">The message reaches Bob. He applies his <b>private key</b> — the one that
         never left his machine.</p>
        <div class="btnrow"><button class="go teal" id="w-dec">🔑 Decrypt with Bob's private key</button></div>
        <div id="w-decout"></div>`;
      $('#w-dec').onclick = async ()=>{
        const res = await post('/api/rsa/decrypt',{private_pem:S.priv, ciphertext:S.ct});
        if(!res.ok){ $('#w-decout').innerHTML = `<div class="err">${res.error}</div>`; return; }
        $('#w-bob').classList.add('win');
        setPacket('✅ delivered', 'open');
        $('#w-decout').innerHTML = `
          <div class="verdict ok">✅ Decrypted successfully</div>
          <div class="reveal"><div class="rh">Bob reads:</div>
            <div class="rb">${esc(res.result.plaintext)}</div></div>
          <div class="wcallout ok"><b>What just happened:</b> two strangers exchanged a private
           message across a channel that was watched the entire time — with no shared password,
           no prior meeting, and nothing secret ever transmitted. This exact mechanism is what
           the padlock in your browser's address bar is doing right now.</div>`;
        render(out, res, {resultRows:[]});
      };
    }
  }

  $('#w-next').onclick = ()=>{ if(step < W_STEPS.length) go(); else reset(); };
  $('#w-back').onclick = ()=>{ if(step > 1){ step -= 2; go(); } };
  $('#w-reset').onclick = ()=> reset();

  function reset(){
    step = 0; S.pub = S.priv = null; S.ct = ''; 
    ['lit','win'].forEach(c=>{$('#w-alice').classList.remove(c);$('#w-bob').classList.remove(c);});
    $('#w-eve').classList.remove('dim');
    $('#w-kpub').classList.remove('on'); $('#w-kprv').classList.remove('on');
    packet.className = 'packet';
    out.classList.remove('show');
    $('#w-next').textContent = 'Start →';
    $('#w-back').style.visibility = 'hidden';
    drawSteps();
    panel.innerHTML = `<p class="wlede">Alice needs to get a message to Bob. Eve is watching every
      byte that crosses the wire. They have no shared password and have never met.
      <b>Press Start</b> and watch how public-key cryptography solves this.</p>`;
  }
  reset();
}

// ---- RSA ----
function rsaTool(){
  return `<h2>RSA public-key crypto</h2>
  <p class="lede">A keypair where the public key encrypts and only the private key decrypts (and
   vice-versa for signing). Security rests on the difficulty of factoring a large number.</p>
  ${EX(`Imagine an <b>open padlock</b> you hand out to everyone (your public key) and the only
    <b>key</b> that opens it, kept in your pocket (your private key). Anyone can snap the padlock
    shut on a message meant for you, but only you can open it. No secret ever had to be shared
    first — that’s the magic that makes secure websites possible.`,
    [`Generate a linked public + private keypair.`,
     `Share the public key freely; guard the private key.`,
     `Someone encrypts <b>to</b> you using your public key.`,
     `Only your private key can decrypt it.`],
    'asym')}
  <div class="row">
    <div><label class="fld">Key size</label>
      <select id="r-bits"><option>2048</option><option>3072</option><option>4096</option></select></div>
    <div style="display:flex;align-items:flex-end"><button class="go" id="r-gen" style="width:100%">Generate keypair</button></div>
  </div>
  <label class="fld">Public key (PEM)</label><textarea id="r-pub" style="min-height:90px"></textarea>
  <label class="fld">Private key (PEM)</label><textarea id="r-priv" style="min-height:90px"></textarea>
  <label class="fld">Plaintext</label><textarea id="r-pt">launch codes: 0000</textarea>
  <div class="btnrow">
    <button class="go" id="r-enc">Encrypt with public →</button>
    <button class="go teal ghost" id="r-dec">← Decrypt with private</button>
  </div>
  <label class="fld">Ciphertext (base64)</label><textarea id="r-ct"></textarea>
  ${outBox()}`;
}
function rsaInit(){
  $('#r-gen').onclick=async()=>{
    const res=await post('/api/rsa/keygen',{bits:parseInt($('#r-bits').value)});
    if(res.ok){$('#r-pub').value=res.result.public_pem;$('#r-priv').value=res.result.private_pem;}
    render($('.out'),res,{});
  };
  $('#r-enc').onclick=async()=>{
    const res=await post('/api/rsa/encrypt',{public_pem:$('#r-pub').value,plaintext:$('#r-pt').value});
    if(res.ok)$('#r-ct').value=res.result.ciphertext;
    render($('.out'),res,{resultRows:[['Ciphertext',res.result?.ciphertext]]});
  };
  $('#r-dec').onclick=async()=>{
    const res=await post('/api/rsa/decrypt',{private_pem:$('#r-priv').value,ciphertext:$('#r-ct').value});
    render($('.out'),res,{resultRows:[['Recovered plaintext',res.result?.plaintext,'teal']]});
  };
}

// ---- SIGNATURES ----
function sigTool(){
  return `<h2>Digital signatures <span class="badge pq">incl. post-quantum</span></h2>
  <p class="lede">Sign with a private key; anyone verifies with the public key. Proves authorship
   and integrity. ML-DSA (Dilithium) resists quantum attacks.</p>
  ${EX(`A signature is the reverse of encryption: you use your <b>private</b> key to seal a
    message, and anyone with your <b>public</b> key can confirm it was really you and that not a
    single character changed. Forging one without the private key is effectively impossible.`,
    [`Generate a signing keypair.`,
     `Sign a message with the <b>private</b> key → a signature.`,
     `Anyone verifies with message + signature + <b>public</b> key.`,
     `Change the message afterwards and verification fails — try it below.`],
    'sig')}
  <label class="fld">Scheme</label>
  <select id="s-scheme"><option>Ed25519</option><option>ECDSA-P256</option>
    <option>RSA-PSS</option><option>ML-DSA (Dilithium)</option></select>
  <div class="btnrow"><button class="go" id="s-gen">Generate signing keypair</button></div>
  <label class="fld">Public key</label><textarea id="s-pub" style="min-height:60px"></textarea>
  <label class="fld">Private key</label><textarea id="s-priv" style="min-height:60px"></textarea>
  <label class="fld">Message</label><textarea id="s-msg">I approve this transaction.</textarea>
  <div class="btnrow">
    <button class="go" id="s-sign">Sign</button>
    <button class="go teal" id="s-verify">Verify</button>
  </div>
  <label class="fld">Signature (base64)</label><textarea id="s-sig"></textarea>
  <p class="hint">Tip: edit the message after signing, then Verify — the check fails.</p>
  ${outBox()}`;
}
function sigInit(){
  $('#s-gen').onclick=async()=>{
    const res=await post('/api/sig/keygen',{scheme:$('#s-scheme').value});
    if(res.ok){$('#s-pub').value=res.result.public_key;$('#s-priv').value=res.result.private_key;}
    render($('.out'),res,{});
  };
  $('#s-sign').onclick=async()=>{
    const res=await post('/api/sig/sign',{scheme:$('#s-scheme').value,private_key:$('#s-priv').value,message:$('#s-msg').value});
    if(res.ok)$('#s-sig').value=res.result.signature;
    render($('.out'),res,{resultRows:[['Signature',res.result?.signature]]});
  };
  $('#s-verify').onclick=async()=>{
    const res=await post('/api/sig/verify',{scheme:$('#s-scheme').value,public_key:$('#s-pub').value,message:$('#s-msg').value,signature:$('#s-sig').value});
    render($('.out'),res,{});
  };
}

// ---- KEY EXCHANGE ----
function kexTool(){
  return `<h2>Key exchange <span class="badge pq">post-quantum + hybrid</span></h2>
  <p class="lede">Two parties agree on a shared secret over a public channel. X25519 is the
   classical workhorse; ML-KEM is quantum-resistant; hybrid combines both so it holds if
   <em>either</em> survives.</p>
  ${EX(`Here’s the near-magic bit: two people who’ve never met can shout numbers at each other
    across a crowded room and both end up knowing the same secret — while everyone listening
    learns <b>nothing</b>. That’s how your browser and a website agree on an encryption key the
    instant you connect.`,
    [`Alice and Bob each make a private value and a matching public value.`,
     `They swap <b>public</b> values over the open channel.`,
     `Each mixes their own private value with the other’s public one.`,
     `The maths lands them on the <b>same</b> shared secret — uncomputable to eavesdroppers.`],
    'kex')}
  <div class="btnrow">
    <button class="go ghost" data-kex="x25519">X25519 (ECDH)</button>
    <button class="go ghost" data-kex="mlkem">ML-KEM-768</button>
    <button class="go" data-kex="hybrid">Hybrid X25519+ML-KEM</button>
  </div>
  <p class="hint">Each run simulates both parties and shows their secrets match.</p>
  ${outBox()}`;
}
function kexInit(){
  document.querySelectorAll('[data-kex]').forEach(b=>b.onclick=async()=>{
    const res=await post('/api/kex/'+b.dataset.kex,{});
    render($('.out'),res,{resultRows:[['Shared secret',res.result?.shared_secret,'teal']]});
  });
}

// ---- ZKP ----
function zkpTool(){
  return `<h2>Zero-knowledge proof</h2>
  <p class="lede">Prove you know a secret without revealing it. This is a Schnorr proof of
   knowledge of a discrete log: the prover convinces the verifier they know x where y=gˣ, yet x
   is never sent.</p>
  ${EX(`Picture proving you know the PIN to a vault <b>without saying the PIN</b>. You answer a
    random challenge in a way only someone who truly knows the secret could — and you can do it
    again and again. The verifier ends up convinced, but learns nothing they could reuse.`,
    [`Prover commits to a random value (hides their secret inside).`,
     `Verifier sends a fresh random challenge.`,
     `Prover responds using the secret + the challenge.`,
     `The response only checks out if the secret is real — but the secret is never sent.`],
    'zkp')}
  <label class="fld">Your secret</label><input type="text" id="z-sec" value="my private passphrase">
  <label class="chk"><input type="checkbox" id="z-tamper"> Simulate a cheating prover (forge the response)</label>
  <div class="btnrow"><button class="go" id="z-go">Run prove ↔ verify</button></div>
  ${outBox()}`;
}
function zkpInit(){
  $('#z-go').onclick=async()=>{
    const res=await post('/api/zkp',{secret:$('#z-sec').value,tamper:$('#z-tamper').checked});
    render($('.out'),res,{});
  };
}

// ---------- boot ----------
const INIT={about:aboutInit,learn:learnInit,walk:walkInit,hash:hashInit,kdf:kdfInit,
  aes:aesInit,files:filesInit,rsa:rsaInit,sig:sigInit,kex:kexInit,zkp:zkpInit};
function jumpWire(root){
  root.querySelectorAll('[data-go]').forEach(el=>el.onclick=()=>show(el.dataset.go));
}
function aboutInit(){jumpWire($('#main'));}
function learnInit(){jumpWire($('#main'));}

function show(id){
  document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('active',b.dataset.id===id));
  const t=TOOLS.find(x=>x.id===id);
  $('#main').innerHTML=`<section class="panel active">${t.build()}</section>`;
  (INIT[id]||(()=>{}))();
  window.scrollTo({top:0,behavior:'smooth'});
}
const nav=$('#nav');
let lastSec='';
TOOLS.forEach(t=>{
  if(t.sec!==lastSec){lastSec=t.sec;
    const s=document.createElement('div');s.className='navsec';s.textContent=t.sec;nav.appendChild(s);}
  const b=document.createElement('button');
  b.className='navbtn';b.dataset.id=t.id;
  b.innerHTML=`${t.name}<small>${t.sub}</small>`;
  b.onclick=()=>show(t.id);
  nav.appendChild(b);
});
show('about');
</script>
</body>
</html>
"""


# =========================================================================
#  WEB APP  (Flask)  — serves the dashboard + JSON API from this one file
# =========================================================================
import os
from flask import Flask, request, jsonify, Response

app = Flask(__name__)


def _json(fn, *keys):
    data = request.get_json(force=True, silent=True) or {}
    try:
        return jsonify(fn(*[data.get(k) for k in keys]))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


@app.route("/api/hash", methods=["POST"])
def api_hash():
    return _json(do_hash, "text", "algo")


@app.route("/api/kdf", methods=["POST"])
def api_kdf():
    d = request.get_json(force=True, silent=True) or {}
    return jsonify(do_kdf(d.get("password", ""), d.get("algo", "Argon2id"),
                          int(d.get("length", 32))))


@app.route("/api/aes/encrypt", methods=["POST"])
def api_aes_enc():
    return _json(aes_encrypt, "plaintext", "password")


@app.route("/api/aes/decrypt", methods=["POST"])
def api_aes_dec():
    return _json(aes_decrypt, "package", "password")


@app.route("/api/file/hash", methods=["POST"])
def api_file_hash():
    return _json(file_hash, "data", "algo", "filename")


@app.route("/api/file/encrypt", methods=["POST"])
def api_file_enc():
    return _json(file_encrypt, "data", "password", "filename")


@app.route("/api/file/decrypt", methods=["POST"])
def api_file_dec():
    return _json(file_decrypt, "blob", "password")


@app.route("/api/rsa/keygen", methods=["POST"])
def api_rsa_keygen():
    d = request.get_json(force=True, silent=True) or {}
    return jsonify(rsa_keygen(int(d.get("bits", 2048))))


@app.route("/api/rsa/encrypt", methods=["POST"])
def api_rsa_enc():
    return _json(rsa_encrypt, "public_pem", "plaintext")


@app.route("/api/rsa/decrypt", methods=["POST"])
def api_rsa_dec():
    return _json(rsa_decrypt, "private_pem", "ciphertext")


@app.route("/api/sig/keygen", methods=["POST"])
def api_sig_keygen():
    return _json(sig_keygen, "scheme")


@app.route("/api/sig/sign", methods=["POST"])
def api_sig_sign():
    return _json(sig_sign, "scheme", "private_key", "message")


@app.route("/api/sig/verify", methods=["POST"])
def api_sig_verify():
    return _json(sig_verify, "scheme", "public_key", "message", "signature")


@app.route("/api/kex/<kind>", methods=["POST"])
def api_kex(kind):
    fn = {"x25519": kex_x25519, "mlkem": kex_mlkem,
          "hybrid": kex_hybrid}.get(kind)
    return jsonify(fn() if fn else {"ok": False, "error": "unknown exchange"})


@app.route("/api/zkp", methods=["POST"])
def api_zkp():
    d = request.get_json(force=True, silent=True) or {}
    return jsonify(zkp_prove_verify(d.get("secret", ""), bool(d.get("tamper"))))


def _open_browser():
    import webbrowser
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == "__main__":
    import threading
    print("")
    print("  CryptX is starting - opening http://127.0.0.1:5000 in your browser.")
    print("  Keep this window open. Close it to stop CryptX.")
    print("")
    threading.Timer(2.0, _open_browser).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
