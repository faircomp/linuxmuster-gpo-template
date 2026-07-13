"""Veyon-specific helper: encrypt a bind password the way Veyon stores it.

Veyon stores LDAP\\BindPassword as the hex of an RSA-OAEP ciphertext produced with
its statically bundled 4096-bit key (core/resources/default-pkey.pem, public part
mirrored in lib/veyon-default-pub.pem). This is reversible obfuscation, NOT a
secret — see docs/VEYON-PLAN.md §5.

NOTE: OAEP is randomized, so the hex is non-deterministic. Encrypt ONCE and store
the result (site.yaml `veyon_bindpw_hex`); never re-encrypt per apply or the value
would change every run and break idempotency.
"""
from __future__ import annotations

import os
import subprocess

from .paths import LIB_DIR

PUBKEY = os.path.join(LIB_DIR, "veyon-default-pub.pem")


def encrypt_bindpw(plaintext: str) -> str:
    """RSA-OAEP(SHA-1)-encrypt with Veyon's public key -> lowercase hex string."""
    if not os.path.exists(PUBKEY):
        raise RuntimeError(f"Veyon public key not found: {PUBKEY}")
    p = subprocess.run(
        ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", PUBKEY,
         "-pkeyopt", "rsa_padding_mode:oaep"],
        input=plaintext.encode("utf-8"), capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("openssl encrypt failed: " + p.stderr.decode(errors="replace"))
    return p.stdout.hex()
