
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


# Classe WindowLogin avant modifications pour implémentation du fichier utils.py.

"""     

        # Password entry (hide with *)
        self.password_entry = tk.Entry(login_root, show="*", width=20)
        self.password_entry.pack()

        # "Connect" button
        self.login_button = (tk.Button(login_root, text="Connect", command=self.check_password))
        self.login_button.pack(pady=20)
        
         if not os.path.exists(PRIMARY_PASSWORD_FILE):
            messagebox.showerror("Error", "primary password file not found.")
            return

        with open(PRIMARY_PASSWORD_FILE, "r") as f:
            data = json.load(f)

        if entered_password == data.get("primary_password"):
            messagebox.showinfo("Success", "Connection approved.")
            self.primary.destroy() # close the window

            window_login_root = tk.Tk()
            window_login_app = MainWindow(window_login_root)
            window_login_root.mainloop()
        else:
            messagebox.showerror("Error", "Wrong password.")
        
        
        """

# load_data avant modifications pour implémentation du fichier utils.py.

""" 
        # If the .json file doesn't exit, create an empty file.
        if not os.path.exists(filepath):
            with open(filepath, "w") as f:
                json.dump({}, f)

        try:
            with open(filepath, "r") as f:
                datas = json.load(f)
                for entry_name, data in datas.items():
                    self.tree.insert("", "end", values=(
                        entry_name,
                        data["website"],
                        data["username"],
                        data["password"]
                    ))
        except (json.JSONDecodeError, KeyError) as e:
            messagebox.showerror("Error", f"Loading .json file {e} impossible.")
            
"""

# edit_entry avant modifications pour implémentation du fichier utils.py.

"""
        # Create the popup window.
                popup = tk.Toplevel(self.primary)
                popup.title("Edit entry")
                popup.geometry("500x400")
                popup.grab_set()
                popup.resizable(True, True)
        
                # Field - Entry
                tk.Label(popup, text="Edit Entry :").pack(pady=(10, 0))
                entryname_entry = tk.Entry(popup)
                entryname_entry.insert(0, entry_old)
                entryname_entry.pack()
        
                # Field - Website/application path
                tk.Label(popup, text="Website :").pack(pady=(10, 0))
                website_entry = tk.Entry(popup)
                website_entry.insert(0, website_old)
                website_entry.pack()
        
                # Field - Username
                tk.Label(popup, text="Username :").pack(pady=(10, 0))
                username_entry = tk.Entry(popup)
                username_entry.insert(0, username_old)
                username_entry.pack()
        
                # Field - Password
                tk.Label(popup, text="Password :").pack(pady=(10,0))
                pwd_entry = tk.Entry(popup, show="*")
                pwd_entry.insert(0, pwd_old)
                pwd_entry.pack()
                
"""