
# Fonction add_entry avant modifications pour implémentation du fichier utils.py.

"""

            # Read the .json file if it exists.
            if os.path.exists("data/passwords.json"):
                with open("data/passwords.json", "r") as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        data = {}
            else:
                data = {}

            # Add new entry
            data[entry] = {
                "website": website,
                "username": username,
                "password": pwd
            }

            # Save in .json file.
            with open("data/passwords.json", "w") as f:
                json.dump(data, f, indent=4)

"""


# Fonction edit_entry avant modifications pour implémentation du fichier utils.py.

"""            
            if os.path.exists("data/passwords.json"):
                try:
                    with open("data/passwords.json", "r") as f:
                        data = json.load(f)
                except json.JSONDecodeError:
                    data = {}
            else:
                data = {}

            # Search the right entry to modify.
            for key, entry in data.items():
                if (key == entry_old and
                    entry["website"] == website_old and
                    entry["username"] == username_old and
                    entry["password"] == pwd_old):

                    data[entry_new] = {
                        "website": website_new,
                        "username": username_new,
                        "password": pwd_new
                    }

                    if entry_new != key:
                        del data[key]
                    break
                    
            # Write in .json file.
            with open("data/passwords.json", "w") as f:
                json.dump(data, f, indent=4)

"""


# Fonction delete_entry avant modifications pour implémentation du fichier utils.py.

"""  
        # Deleting in .json file.
            if os.path.exists("data/passwords.json"):
                try:
                    with open("data/passwords.json", "r") as f:
                        data = json.load(f)
                except json.JSONDecodeError:
                    data = {}
            else:
                data = {}
    
            if entry in data:
                item = data[entry]
                if (
                    item.get("website") == website and
                    item.get("username") == username and
                    item.get("password") == pwd
                ):
                    del data[entry]
                else:
                    messagebox.showerror("Error", "Entry data doesn't match, deletion cancelled.")
                    return
            else:
                messagebox.showerror("Error", "Entry not found.")
                return
    
            with open("data/passwords.json", "w") as f:
                json.dump(data, f, indent=4)

"""


# Fonction save_json avant modifications pour implémentation du fichier utils.py.

"""    
            def save_json(self):
            filepath = "data/passwords.json"
            datas = []
    
            for child in self.tree.get_children():
                values = self.tree.item(child)["values"]
                datas.append({
                    "entry": values[0],
                    "website": values[1],
                    "username": values[2],
                    "password": values[3]
                })
            try:
                with open(filepath, "w") as f:
                    json.dump(datas, f, indent=4)
            except IOError as e:
                messagebox.showerror("Error", f"Error when saving password file: {e}")
            
"""