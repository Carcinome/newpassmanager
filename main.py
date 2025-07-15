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
    if not os.path.exists(PASSWORDS_FILE):
        return {} # No passwords already registered.
    with open(PASSWORDS_FILE, "r") as f:
        return json.load(f)

def save_passwords(passwords):
    """Save the password dictionary in the passwords.json file."""
    with open(PASSWORDS_FILE, "w") as f:
        json.dump(passwords, f, indent=4)




if __name__ == "__main__":
    init_storage()