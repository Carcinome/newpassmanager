"""Here, the main code for the passwords' manager."""

import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# path to the primary password storage file
PRIMARY_PASSWORD_FILE = "data/primary_password.json"
PASSWORDS_FILE = "data/passwords.json"
SALT = b"azertyuiop123456"


def init_storage():
    """Create the primary_password.json file if it does not exist."""
    if not os.path.exists(PRIMARY_PASSWORD_FILE):
        print("No primary password found, creating it.")
        primary_password = input("Create your primary password : ")
        with open(PRIMARY_PASSWORD_FILE, "w") as f:
            json.dump({"primary_password": primary_password}, f)
        print("Primary password has been created.")
    else:
        with open(PRIMARY_PASSWORD_FILE, "r") as f:
            data = json.load(f)
        primary_password = input("Enter the primary password : ")
        if primary_password != data["primary_password"]:
            print("Wrong password.")
            exit()
    return derive_key(primary_password)


def load_passwords():
    """Load the passwords.json file if it exists."""
    if not os.path.exists(PASSWORDS_FILE) or os.path.getsize(PASSWORDS_FILE) == 0:
        return {} # No passwords already registered.
    with open(PASSWORDS_FILE, "r") as f:
        return json.load(f)


def ensure_password_file():
    """Ensure the password file is created."""
    if not os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, "w") as f:
            json.dump({}, f)


def save_passwords(passwords):
    """Save the password dictionary in the passwords.json file."""
    with open(PASSWORDS_FILE, "w") as f:
        json.dump(passwords, f, indent=4)


def add_password(fernet_instance):
    """Add a new password for a website in the passwords.json file."""
    entry_name = input("New entry name : ").strip()
    website = input("New website url of application path : ").strip()
    username = input("New username : ").strip()
    pwd = input("New password : ").strip()

    encrypted_password = fernet_instance.encrypt(pwd.encode()).decode()

    passwords = load_passwords()
    passwords[entry_name] = {
        "website" : website,
        "username" : username,
        "password" : encrypted_password
    }
    save_passwords(passwords)
    print(f"Password crypted and saved for {entry_name}.")


def delete_password():
    """Delete an entry from the passwords.json file."""
    passwords = load_passwords()
    if not passwords:
        print("No passwords found.")
        return

    entry_name = input("Entry to delete : ").strip()

    if entry_name in passwords:
        deleting_confirmation = input(f"Are you sure you want to delete this : {entry_name}? (y/n) ").lower()
        if deleting_confirmation == "y":
            del passwords[entry_name]
            save_passwords(passwords)
            print (f"Password deleted successfully for {entry_name}.")
        else:
            print("Password not deleted.")
    else:
        print(f"No password found for {entry_name}.")


def modify_password(fernet_instance):
    """Modify an entry from the passwords.json file."""
    passwords = load_passwords()
    if not passwords:
        print("No passwords found.")
        return

    entry_name = input("Entry to edit password : ").strip()

    if entry_name in passwords:
        print(f"Entry found : {entry_name}.")
        print(f"Current username : {passwords[entry_name]['username']}")

        new_username = input("New username (leave blank to not change) : ").strip()
        new_pwd = input("New password (leave blank to not change) : ").strip()

        if new_username:
            passwords[entry_name]['username'] = new_username
        if new_pwd:
            encrypted_password = fernet_instance.encrypt(new_pwd.encode()).decode()
            passwords[entry_name]['pwd'] = encrypted_password

        save_passwords(passwords)
        print(f"Password changed successfully for {entry_name}.")
    else:
        print(f"No password found for {entry_name}.")


def view_passwords(fernet_instance):
    """View all passwords registered."""
    passwords = load_passwords()
    if not passwords:
        print("No passwords found.")
        return

    print("\nPasswords registered : ")
    for entry_name, credentials in passwords.items():
        try:
            decrypted_password = fernet_instance.decrypt(credentials["password"].encode()).decode()
        except InvalidToken:
            decrypted_password = "Passwords unreadable, wrong key."

        print(f"Entry name : {entry_name}")
        print(f"Website/apply path : {credentials['website']}")
        print(f"Username : {credentials['username']}")
        print(f"Password : {decrypted_password}")
        print("-" * 30)


def derive_key(primary_password: str) -> Fernet:
    """Derive a Fernet key from a primary password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(primary_password.encode()))
    return Fernet(key)


if __name__ == "__main__":
    fernet = init_storage()
    ensure_password_file()

    while True:
        print("\n Menu : ")
        print("1. Add a new entry")
        print("2. View all entry registered")
        print("3. Edit an entry")
        print("4. Delete an entry")
        print("5. Exit")

        choice = input("Enter your choice : ")
        if choice == "1":
            add_password(fernet)
        elif choice == "2":
            view_passwords(fernet)
        elif choice == "3":
            modify_password(fernet)
        elif choice == "4":
            delete_password()
        elif choice == "5":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Try again.")