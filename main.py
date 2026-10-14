import getpass
import os
import secrets
import sqlite3
import string

from cryptography.exceptions import InvalidTag

from database import *
from crypto import *

PASSWORD_CHARACTERS = string.ascii_letters + string.digits + "!@#$%^&*"


# Builds a random password
def generate_password(length=20):
    return "".join(secrets.choice(PASSWORD_CHARACTERS) for _ in range(length))


# A saved password is stored as its nonce followed by the ciphertext
def pack(nonce, ciphertext):
    return nonce + ciphertext


def unpack(stored):
    return stored[:NONCE_LENGTH], stored[NONCE_LENGTH:]


# Makes a new user plus the vault key that protects their passwords
def create_account():
    username = input("Enter a username: ")
    password = getpass.getpass("Enter a master password: ")

    salt = os.urandom(SALT_LENGTH)
    vault_key = generate_vault_key()
    nonce, encrypted_vault_key = encrypt_vault_key(vault_key, derive_key(password, salt))

    try:
        user_id = create_user(username, salt, encrypted_vault_key, nonce)
    except sqlite3.IntegrityError:
        print("That username is taken.")
        return None

    print(f"Welcome, {username}.")
    return user_id, vault_key


# Unlocks an existing user's vault key with their master password
def unlock_account():
    username = input("Which user are you?: ")
    user = get_user(username)

    if user is None or user["salt"] is None:
        print("No user by that name.")
        return None

    password = getpass.getpass("Master password: ")

    try:
        vault_key = decrypt_vault_key(
            user["vault_key"],
            user["vault_key_nonce"],
            derive_key(password, user["salt"]),
        )
    except InvalidTag:
        print("Wrong master password.")
        return None

    print(f"Welcome back, {username}.")
    return user["id"], vault_key


# 1.) Pick a user, 2.) unlock their vault, 3.) hand back the key
def login():
    while True:
        option = input("\nL to login, C to create a new user \n>> ")

        if option.lower() == "c":
            account = create_account()
        elif option.lower() == "l":
            account = unlock_account()
        else:
            print("Users:", ", ".join(user["username"] for user in list_users()))
            continue

        # Only leave once a vault is actually open
        if account is not None:
            return account


# 5.) Show a saved password
def retrieve_password(user_id, vault_key):
    credentials = list_credentials(user_id)

    if not credentials:
        print("Nothing saved yet.")
        return

    for credential in credentials:
        print(f"{credential['id']}. {credential['site_name']} ({credential['username']})")

    choice = input("Which number?: ")
    credential = get_credential(choice, user_id) if choice.isdigit() else None

    if credential is None:
        print("No password with that number.")
        return

    nonce, ciphertext = unpack(credential["password"])
    print(f"Password: {decrypt_credential(ciphertext, nonce, vault_key)}")

    if credential["notes"]:
        print(f"Notes: {credential['notes']}")


# 6.) Name the password, 7.) generate or type it, 8.) save it encrypted
def add_password(user_id, vault_key):
    site_name = input("Site name: ")
    username = input("Username for that site: ")

    if input("G to generate a password, anything else to type your own \n>> ").lower() == "g":
        password = generate_password()
        print(f"Generated: {password}")
    else:
        password = getpass.getpass("Password: ")

    notes = input("Notes (optional): ") or None

    nonce, ciphertext = encrypt_credential(password, vault_key)
    save_credential(user_id, site_name, username, pack(nonce, ciphertext), notes)
    print(f"Saved {site_name}.")


def main():
    init_db()

    user_id, vault_key = login()

    # 4.) Ask if want to retreive or add password
    while True:
        option = input("\nR to retrieve a password, A to add one, Q to quit \n>> ")

        if option.lower() == "r":
            retrieve_password(user_id, vault_key)
        elif option.lower() == "a":
            add_password(user_id, vault_key)
        elif option.lower() == "q":
            return


if __name__ == "__main__":
    main()
