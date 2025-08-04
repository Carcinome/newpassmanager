
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
                
                
                
                for label_text, attribut in [("Entry :", "e"), ("Website :", "w"), ("Username :", "u"), ("Password :", "p")]:
            tk.Label(popup, text=label_text).pack(pady=(30, 5))
            new_entry = tk.Entry(popup, show="*" if label_text == "Password :" else "")
            setattr(self, f"add_{attribut}_entry", new_entry)
            new_entry.pack()
            
            entries_to_modify = []
        for i, label_text in enumerate(("Entry :", "Website :", "Username :", "Password :")):
            tk.Label(popup, text=label_text).pack(pady=(30, 5))
            entry_to_modify = tk.Entry(popup, show="*" if i ==3 else "")
            entry_to_modify.insert(0, old_entry[i])
            entry_to_modify.pack()
            entries_to_modify.append(entry_to_modify)
                
"""

# save_entry avant modifications pour implémentation du fichier utils.py.

"""        

            def entry_update():
            entry_new = entryname_entry.get().strip()
            website_new = website_entry.get().strip()
            username_new = username_entry.get().strip()
            pwd_new = pwd_entry.get().strip()

            if not entry_new or not website_new or not username_new or not pwd_new:
                messagebox.showwarning("Fields missing!", "Please fill all fields before saving.")

            # Update selected line.
            self.tree.item(selected_entry, values=(entry_new, website_new, username_new, pwd_new))

            # Load the passwords.json file via utils.py's function.
            data = load_passwords()

            if entry_new != entry_old and entry_old in data:
                del data[entry_old]

            data[entry_new] = {
                "website": website_new,
                "username": username_new,
                "password":pwd_new
            }
            save_passwords(data)
            popup.destroy()

        # "Save" button
        tk.Button(popup, text="Save", command=save).pack(pady=15)
        
        
"""

# delete_entry avant modifications pour implémentation du fichier utils.py.

"""
    def delete_entry(self):
        # Take the selected element.
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning("No entry selected", "Please select an entry.")
            return

        # Extract the values of the line selected, key and data.
        entry_old, website_old, username_old, pwd_old = self.tree.item(selected_entry, "values")

        confirm = messagebox.askyesno("Confirm deleting", "Would you really want to delete this entry?")

        if not confirm:
            return

        self.tree.delete(selected_entry)

        # Load the passwords.json file via utils.py's function.
        data = load_passwords()

        # Delete the matched key in the python dictionary.
        if entry_old in data:
            del data[entry_old]
            save_passwords(data)
        else:
            messagebox.showerror("Error", "Entry not found in data file. Please try again.")
            
"""

# fichier de lancement avant modifications pour implémentation du fichier utils.py.

"""
        if __name__ == "__main__":
    if not os.path.exists(PRIMARY_PASSWORD_FILE):
        root = tk.Tk()
        app = InitiatePrimaryWindow(root)
    else:
        root = tk.Tk()
        app = WindowLogin(root)

    root.mainloop()

"""