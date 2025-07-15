import json
import os

# path to the master password storage file
MASTER_PASSWORD_FILE = "data/master.json"
PASSWORDS_FILE = "data/passwords.json"

def init_storage():
    """Create the master.json file if it does not exist."""
    if not os.path.exists(MASTER_PASSWORD_FILE):
        print("No master password found, creating it.")
        master = input("Create your master password : ")
        with open(MASTER_PASSWORD_FILE, "w") as f:
            json.dump({"master_password": master}, f)
        print("Master password has been created.")
    else:
        with open(MASTER_PASSWORD_FILE, "r") as f:
            data = json.load(f)
        trial = input("Enter the master password : ")
        if trial == data["master_password"]:
            print("access granted.")
        else:
            print("access denied.")

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

def add_password():
    """Add a new password for a website in the passwords.json file."""
    entry_name = input("New entry name : ").strip()
    website = input("New website url of application path : ").strip()
    username = input("New username : ").strip()
    pwd = input("New password : ").strip()

    passwords = load_passwords()
    passwords[entry_name] = {
        "website" : website,
        "username" : username,
        "password" : pwd
    }
    save_passwords(passwords)
    print(f"Password saved for {entry_name}.")

def view_passwords():
    """View all passwords registered."""
    passwords = load_passwords()
    if not passwords:
        print("No passwords found.")
        return

    print("\nPasswords registered : ")
    for entry_name, credentials in passwords.items():
        print(f"Entry name : {entry_name}")
        print(f"Website/apply path : {credentials['website']}")
        print(f"Username : {credentials['username']}")
        print(f"Password : {credentials['password']}")
        print("-" * 30)

if __name__ == "__main__":
    init_storage()
    ensure_password_file()
    while True:
        print("\n Menu : ")
        print("1. Add a new entry")
        print("2. View all passwords registered")
        print("3. Exit")

        choice = input("Enter your choice : ")
        if choice == "1":
            add_password()
        elif choice == "2":
            view_passwords()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Try again.")