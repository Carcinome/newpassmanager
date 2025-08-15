"""This file si for making a Graphic User Interface, for avoid command lines interface for customers."""


import tkinter as tk
import json
from tkinter import messagebox, ttk

from cryptography.fernet import InvalidToken

from utils import (
    PRIMARY_PASSWORD_FILE,
    load_passwords,
    save_passwords,
    encrypt_password,
    decrypt_password,
    get_or_create_salt,
    derive_fernet_key,
)

from src.vault import load_encrypted_vault, save_encrypted_vault, Vault, Entry

class InitiatePrimaryWindow:
    """
    For creating a primary password if it doesn't exist.
    Display two fields (password and confirmation) and one 'create' button.
    """
    def __init__(self, primary):

        self.primary = primary

        # Main text.
        self.primary.title("Create primary password")
        self.primary.geometry("400x300")
        self.primary.resizable(False, False)

        # Password field.
        tk.Label(self.primary, text="Enter a new primary password:").pack(pady=(20, 5))
        self.pwd_entry = tk.Entry(self.primary, show="*", width=30)
        self.pwd_entry.pack()

        # Confirm field.
        tk.Label(self.primary, text="Confirm password:").pack(pady=(10, 5))
        self.confirm_entry = tk.Entry(self.primary, show="*", width=30)
        self.confirm_entry.pack()

        # "Create" button.
        tk.Button(self.primary, text="Create", command=self.save_primary_password).pack(pady=20)

    def save_primary_password(self):
        """
        For saving primary password.
        """
        password = self.pwd_entry.get().strip()
        password_confirmation = self.confirm_entry.get().strip()

        if not password or not password_confirmation:
            messagebox.showerror("Error", "All fields are required.")
            return

        if password != password_confirmation:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        with open(PRIMARY_PASSWORD_FILE, "w") as f:
            json.dump({"primary_password": password}, f)

        # Create the salt.
        get_or_create_salt()

        messagebox.showinfo("Success", "Primary password saved.")
        # close the window.
        self.primary.destroy()
        # Open the connection window
        login_root = tk.Tk()
        WindowLogin(login_root)
        login_root.mainloop()


class WindowLogin:
    """
    Login screen. Ask for the primary password.
    """
    def __init__(self, login_root):
        self.login_root = login_root
        self.fernet = None

        self.login_root.title("Connection - Password manager")
        self.login_root.geometry("600x400")
        self.login_root.resizable(False, False)

        # Main text
        tk.Label(login_root, text="Enter your primary password :").pack(pady=(30, 5))
        self.password_entry = tk.Entry(login_root, show="*", width=30); self.password_entry.pack()
        tk.Button(login_root, text="Login", command=self.check_password).pack(pady=20)
        self.password_entry.pack()

    def check_password(self):
        """
        A check for the primary password before the access to databases.
        """
        entered_password = self.password_entry.get().strip()
        # 1. Read the password stocked in the .json file.
        try:
            with open(PRIMARY_PASSWORD_FILE,  "r") as f:
                stored_password = json.load(f).get("primary_password", "")
        except FileNotFoundError:
            messagebox.showerror("Error", "No primary password found. Please create one first.")
            return

        # 2. Compare.
        if entered_password != stored_password:
            messagebox.showerror("Error", "Invalid primary password.")
            return

        # 3. Derive the Fernet key from the password entered.
        salt = get_or_create_salt()
        self.fernet = derive_fernet_key(entered_password, salt)

        # 4. Load the vault (or empty if it doesn't exist yet).
        from pathlib import Path
        VAULT_PATH = Path("data") / "vault.enc"
        self.vault = load_encrypted_vault(self.fernet, str(VAULT_PATH))

        # 5. Open the primary the main window.
        messagebox.showinfo("Success", "Login successful.")
        self.login_root.destroy()
        main_root = tk.Tk()
        MainWindow(main_root, self.fernet, self.vault, str(VAULT_PATH))
        main_root.mainloop()


class MainWindow:
    """Main window:
    - Display all credentials/passwords.
    - Possibility to add, modify, remove and show a password.
    """
    def __init__(self, primary_main, fernet, vault, vault_path):
        self.primary_main = primary_main
        self.fernet = fernet
        self.vault = vault
        self.vault_path = vault_path

        self.primary_main.title("Password manager")
        self.primary_main.geometry("1000x800")
        self.primary_main.resizable(True, True)

        # Array - Treeview.
        columns = ("entry", "website or application path", "username", "password")
        self.tree = ttk.Treeview(primary_main, columns=columns, show="headings")
        for c, text in zip(columns, ("entry", "website or application path", "username", "password")):
            self.tree.heading(c, text=text)
            self.tree.column(c, width=150)
        self.tree.pack(fill="both", expand=True, pady=(10, 0))

        # Buttons
        button_frame = tk.Frame(primary_main)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Add", command=self.add_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text="Edit", command=self.edit_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text="Delete", command=self.delete_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text="Show", command=self.show_password).pack(side="left", padx=10)
        tk.Button(button_frame, text="Copy", command=self.copy_password).pack(side="left", padx=10)

        self.load_data()

    def load_data(self):
        """
        Load the passwords crypted and display:
                - 3 first columns cleared
                - The 'password' column on masked form (******).
        """
        # Clean the Treeview.
        self.tree.delete(*self.tree.get_children())
        # Read the passwords.json file's dictionary.
        data = self.vault.to_dict_entry()
        # For all entries, decrypt and mask datas.
        for entry, info in data.items(): # 0.3.5
            encrypt = info.get("password", "")
            try:
                clear_pwd = decrypt_password(self.fernet, encrypt)
                masked_pwd = "•" * (len(clear_pwd) * 12)
            except (InvalidToken,TypeError):
                masked_pwd = "Error"
            self.tree.insert(
                "", "end",
                values=(
                    entry,
                    info.get("website", ""),
                    info.get("username", ""),
                    masked_pwd
                )
            )

    def add_entry(self):
        """
        Open a popup for entering a new entry.
        Write a new entry name, website or application path, username and password.
        Finally, save it and reload the array.
        """
        popup = tk.Toplevel(self.primary_main)
        popup.title("Add new entry")
        popup.geometry("600x400")
        popup.grab_set()

        # Fields.
        tk.Label(popup, text="Entry :").pack(pady=(30, 5))
        new_entry_entry = tk.Entry(popup); new_entry_entry.pack()
        tk.Label(popup, text="Website or application path :").pack(pady=(30, 5))
        new_website_entry = tk.Entry(popup); new_website_entry.pack()
        tk.Label(popup, text="Username :").pack(pady=(30, 5))
        new_username_entry = tk.Entry(popup); new_username_entry.pack()
        tk.Label(popup, text="Password :").pack(pady=(30, 5))
        new_password_entry = tk.Entry(popup, show="*"); new_password_entry.pack()

        # "Save" button.
        def save():
            entry       = new_entry_entry.get().strip()
            website     = new_website_entry.get().strip()
            username    = new_username_entry.get().strip()
            pwd         = new_password_entry.get().strip()

            if not (entry and website and username and pwd):
                messagebox.showerror("Fields must be filled!", "Please fill all fields before saving.")
                return
            # Load the passwords.json file via utils.py's function.
            data = load_passwords()
            data[entry] = {
                "website": website,
                "username": username,
                "password":encrypt_password(self.fernet, pwd)
            }
            save_passwords(data)
            popup.destroy()
            self.load_data()

        tk.Button(popup, text="Save", command=save).pack(pady=(30, 5))

    def edit_entry(self):
        """
        Open a popup for editing a selected entry.
        Finally, update the passwords.json file and reload the array.
        """
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning("No entry selected", "Please select an entry.")
            return

        # Take values from the selected line.
        entry_old, website_old, username_old, pwd_old = self.tree.item(selected_entry, "values")
        # Popup creation.
        popup = tk.Toplevel(self.primary_main)
        popup.title("Edit entry")
        popup.geometry("700x500")
        popup.grab_set()

        # Fields autoloaded.
        tk.Label(popup, text="Entry :").pack(pady=(30, 5))
        entry_input = tk.Entry(popup)
        entry_input.insert(0, entry_old)
        entry_input.pack()

        tk.Label(popup, text="Website or application path :").pack(pady=(30, 5))
        website_input = tk.Entry(popup)
        website_input.insert(0, website_old)
        website_input.pack()

        tk.Label(popup, text="Username :").pack(pady=(30, 5))
        username_input = tk.Entry(popup)
        username_input.insert(0, username_old)
        username_input.pack()

        tk.Label(popup, text="Password :").pack(pady=(30, 5))
        password_input = tk.Entry(popup, show="*")
        password_input.insert(0, pwd_old)
        password_input.pack()

        # Function for saving modifications.
        def entry_save():
        # Read the new fields.
            entry_new = entry_input.get().strip()
            website_new = website_input.get().strip()
            username_new = username_input.get().strip()
            pwd_new = password_input.get().strip()


            if not (entry_new and website_new and username_new and pwd_new):
                messagebox.showerror("Error", "All fields are required.")
                return

            # Treeview update.
            self.tree.item(selected_entry, values=(entry_new, website_new, username_new, pwd_new))
            # Loading of the passwords.json file.
            data = load_passwords()
            # if the entry key changes, deleting the oldest key.
            if entry_new != entry_old and entry_old in data:
                del data[entry_old]
            # Saving with the good values.
            data[entry_new] = {
                "website": website_new,
                "username": username_new,
                "password": encrypt_password(self.fernet, pwd_new)
            }
            # Saving in the passwords.json file.
            save_passwords(data)
            # Quit and reload the window.
            popup.destroy()
            self.load_data()

        tk.Button(popup, text="Update entry", command=entry_save).pack(pady=20)

    def delete_entry(self):
        """
        Delete a selected entry from the passwords.json file and the array.
        """
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning("No entry selected", "Please select an entry first.")
            return

        entry_to_delete = self.tree.item(selected_entry, "values")[0]
        if not messagebox.askyesno("Please confirm deletion", f"Deleting {entry_to_delete}?"):
            return

        data = load_passwords()
        if entry_to_delete in data:
            del data[entry_to_delete]
            save_passwords(data)
        self.load_data()

    def show_password(self):
        """
        Show the password cleared for the selected entry in a popup.
        """
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning("No entry selected", "Please select an entry first.")
            return
            # Unic ID of the selected line.
        item_id = selected_entry[0]

        entry_to_show = self.tree.item(selected_entry, "values")[0]
        data = load_passwords()
        token = data.get(entry_to_show, {}).get("password", "")
        try:
            clear_pwd = decrypt_password(self.fernet, token)
        except InvalidToken:
            messagebox.showerror("Error", "Cannot clear password.")
            return
        # Display the cleared password in the cell.
        self.tree.set(item_id, "password", clear_pwd)
        # Prepare the mask (oversize in comparison of password).
        mask = "•" * (len(clear_pwd) * 12)

        # Planification of an establishment for the mask in 15 seconds.
        def hide_password_again():
            if item_id in self.tree.get_children():
                self.tree.set(item_id, "password", mask)

        # After 15 seconds, restart hide_password_again.
        self.primary_main.after(15_000, hide_password_again)

    def copy_password(self):
        """
        Copy the password to the clipboard from the selected line.
        """
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning("No entry selected", "Please select a line first.")
            return
        item_id = selected_entry[0]

        # Recuperation of the key and read the crypted token.
        entry_name = self.tree.item(item_id, "values")[0]
        data = load_passwords()
        token = data.get(entry_name, {}).get("password", "")

        # Try to decrypt.
        try:
            clear_pwd = decrypt_password(self.fernet, token)
        except InvalidToken:
            messagebox.showerror("Error", "Cannot decrypt password.")
            return

        # Copy the password in the Tkinter's clipboard.
        # Remplace the copied data and add the password after.
        self.primary_main.clipboard_clear()
        self.primary_main.clipboard_append(clear_pwd)
        # Notify the user.
        messagebox.showinfo("Password copied to clipboard", f"Password for {entry_name} is copied to clipboard.")