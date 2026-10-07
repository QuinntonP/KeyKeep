# All methods dealing with encryption and decryption

from argon2.low_level import Type, hash_secret_raw

KEY_LENGTH = 32
SALT_LENGTH = 16
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
def generate_vault_key():
    pass


# Encrypts the vault key using the key made from the master password
def encrypt_vault_key():
    pass


# Decrypts the vault key after the user enters the correct master password
def decrypt_vault_key():
    pass


# Encrypts a password before it is sent to the database
def encrypt_credential():
    pass


# Decrypts a password after it is retrieved from the database
def decrypt_credential():
    pass