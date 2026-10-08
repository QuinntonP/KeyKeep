# All methods dealing with encryption and decryption

import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 1


# Creates a key from the user's master password.
# salt must be 16 bytes; the caller generates and stores it.
def derive_key(master_password: str, salt: bytes) -> bytes:
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"salt must be {SALT_LENGTH} bytes")

    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )


# Creates a random vault key used to encrypt passwords
def generate_vault_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


# Encrypts the vault key using the key made from the master password.
# Returns (nonce, ciphertext). The caller stores both.
def encrypt_vault_key(vault_key: bytes, unlock_key: bytes) -> tuple[bytes, bytes]:
    if len(unlock_key) != KEY_LENGTH:
        raise ValueError(f"unlock key must be {KEY_LENGTH} bytes")

    aesgcm = AESGCM(unlock_key)
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = aesgcm.encrypt(nonce, vault_key, None)
    return nonce, ciphertext


# Decrypts the vault key after the user enters the correct master password.
# A wrong unlock key raises cryptography.exceptions.InvalidTag.
def decrypt_vault_key(encrypted_vault_key: bytes, nonce: bytes, unlock_key: bytes) -> bytes:
    if len(unlock_key) != KEY_LENGTH:
        raise ValueError(f"unlock key must be {KEY_LENGTH} bytes")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(f"nonce must be {NONCE_LENGTH} bytes")

    aesgcm = AESGCM(unlock_key)
    return aesgcm.decrypt(nonce, encrypted_vault_key, None)


# Encrypts a password before it is sent to the database.
# Returns (nonce, ciphertext). The caller stores both.
def encrypt_credential(plaintext: str, vault_key: bytes) -> tuple[bytes, bytes]:
    if len(vault_key) != KEY_LENGTH:
        raise ValueError(f"vault key must be {KEY_LENGTH} bytes")

    aesgcm = AESGCM(vault_key)
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext


# Decrypts a password after it is retrieved from the database.
# A wrong vault key raises cryptography.exceptions.InvalidTag.
def decrypt_credential(ciphertext: bytes, nonce: bytes, vault_key: bytes) -> str:
    if len(vault_key) != KEY_LENGTH:
        raise ValueError(f"vault key must be {KEY_LENGTH} bytes")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(f"nonce must be {NONCE_LENGTH} bytes")

    aesgcm = AESGCM(vault_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")