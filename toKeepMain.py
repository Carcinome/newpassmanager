# Contenance de main.py avant modification pour mise en place croisement de fichiers et optimisation.

"""
                                        def init_storage():

                Create the primary_password.json file if it does not exist.

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

                Load the passwords.json file if it exists.

                if not os.path.exists(PASSWORDS_FILE) or os.path.getsize(PASSWORDS_FILE) == 0:
                    return {} # No passwords already registered.
                with open(PASSWORDS_FILE, "r") as f:
                    return json.load(f)


            def ensure_password_file():

                Ensure the password file is created.

                if not os.path.exists(PASSWORDS_FILE):
                    with open(PASSWORDS_FILE, "w") as f:
                        json.dump({}, f)


                    def save_passwords(passwords):

                Save the password dictionary in the passwords.json file.

                with open(PASSWORDS_FILE, "w") as f:
                    json.dump(passwords, f, indent=4)


                    def add_password(fernet_instance):

                    Add a new password for a website in the passwords.json file.

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

                    Delete an entry from the passwords.json file.

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

                    Modify an entry from the passwords.json file.

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
                            passwords[entry_name]['password'] = encrypted_password

                        save_passwords(passwords)
                        print(f"Password changed successfully for {entry_name}.")
                    else:
                        print(f"No password found for {entry_name}.")


                def view_passwords(fernet_instance):

                    View all passwords registered.

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

                    Derive a Fernet key from a primary password.

                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=SALT,
                        iterations=100_000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(primary_password.encode()))
                    return Fernet(key)

"""