# All methods dealing with encryption and decryption


# Creates a key from the user's master password
def derive_key():
    pass


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