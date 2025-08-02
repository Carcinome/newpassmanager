"""This file si for making a Graphic User Interface, for avoid command lines interface for customers."""


import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

from cryptography.fernet import InvalidToken

from utils import (
    PRIMARY_PASSWORD_FILE,
    load_passwords,
    save_passwords,
    encrypt_password,
    decrypt_password,
)


class InitiatePrimaryWindow:
    """
    For creating a primary password if it doesn't exist.
    Display two fields (password and confirmation) and one 'create' button.
    """
    def __init__(self, primary, fernet):

        self.primary = primary
        self.fernet = fernet

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
            f.write(password)

        messagebox.showinfo("Success", "Primary password saved.")
        self.primary.destroy() # close the window.

        # Open the connection window
        login_root = tk.Tk()
        WindowLogin(login_root, self.fernet)
        login_root.mainloop()


class WindowLogin:
    """
    Login screen. Ask for primary password.
    """
    def __init__(self, login_root, fernet):
        self.login_root = login_root
        self.fernet = fernet
        self.login_root.title("Connection - Password manager")
        self.login_root.geometry("400x300")
        self.login_root.resizable(False, False)

        # Main text
        tk.Label(login_root, text="Enter your primary password :").pack(pady=(30, 5))
        tk.Button(login_root, text="Login", command=self.check_password).pack(pady=20)
        self.password_entry = tk.Entry(login_root, show="*", width=30)
        self.password_entry.pack()


    def check_password(self):
        """
        A check for primary password before the access to databases.
        """
        entered_password = self.password_entry.get().strip()
        try:
            decrypt_password(self.fernet, encrypt_password(self.fernet, "test"))
        except InvalidToken:
            messagebox.showerror("Error", "Invalid primary password.")
            return

        messagebox.showinfo("Success", "Login successful.")
        self.login_root.destroy()
        # Call for the main window here.
        main_root = tk.Tk()
        MainWindow(main_root, self.fernet)
        main_root.mainloop()


class MainWindow:
    """Main window:
    - Display all credentials/passwords.
    - Possibility to add, modify, remove and show a password.
    """
    def __init__(self, primary_main, fernet):
        self.primary_main = primary_main
        self.fernet = fernet

        self.add_e_entry: Optional[tk.Entry] = None
        self.add_w_entry: Optional[tk.Entry] = None
        self.add_u_entry: Optional[tk.Entry] = None
        self.add_p_entry: Optional[tk.Entry] = None

        self.primary_main.title("Password manager")
        self.primary_main.geometry("1000x800")
        self.primary_main.resizable(True, True)

        # Array - Treeview.
        columns = ("entry", "website", "username", "password")
        self.tree = ttk.Treeview(primary_main, columns=columns, show="headings")
        for c, text in zip(columns, ("entry", "website", "username", "password")):
            self.tree.heading(c, text=text)
            self.tree.column(c, width=150)
        self.tree.pack(fill="both", expand=True, pady=(10, 0))

        # Buttons
        button_frame = tk.Frame(primary_main)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Add", command=self.add_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text="Edit", command=self.edit_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text="Delete", command=self.delete_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text="Show", command=self.show_passwords).pack(side="left", padx=10)

        self.load_data()

    def load_data(self):
        """
        Read passwords.json, decrypt any passwords and increment the Treeview.
        """
        self.tree.delete(*self.tree.get_children())
        data = load_passwords()
        for entry, info in data.items():
            encrypt = info.get("password", "")
            try:
                clear = decrypt_password(self.fernet, encrypt)
            except InvalidToken:
                clear = "Error"
            self.tree.insert(
                "", "end",
                values=(
                    entry,
                    info.get("website", ""),
                    info.get("username", ""),
                    clear
                )
            )


    def add_entry(self):
        """
        Open a popup for entering a new entry.
        Write new entry name, website or application path, username and password.
        Finally, save it and reload the array.
        """
        popup = tk.Toplevel(self.primary_main)
        popup.title("Add new entry")
        popup.geometry("400x300")
        popup.grab_set()

        # Fields.
        for label_text, attribut in [("Entry :", "e"), ("Website :", "w"), ("Username :", "u"), ("Password :", "p")]:
            tk.Label(popup, text=label_text).pack(pady=(30, 5))
            new_entry = tk.Entry(popup, show="*" if label_text == "Password :" else "")
            setattr(self, f"add_{attribut}_entry", new_entry)
            new_entry.pack()


        # "Save" button.
        def save():
            entry       = self.add_e_entry.get().strip()
            website     = self.add_w_entry.get().strip()
            username    = self.add_u_entry.get().strip()
            pwd         = self.add_p_entry.get().strip()

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

        # Take values from selected line.
        entry_old, website_old, username_old, pwd_old = self.tree.item(selected_entry, "values")
        popup = tk.Toplevel(self.primary_main)
        popup.title("Edit entry")
        popup.geometry("400x300")
        popup.grab_set()

        # Fields autoloaded.
        for i, label_text in enumerate(("Entry :", "Website :", "Username :", "Password :")):
            tk.Label(popup, text=label_text).pack(pady=(30, 5))
            entry_to_modify = tk.Entry(popup, show="*" if i ==3 else "")
            entry_to_modify.insert(0, [entry_old, website_old, username_old, pwd_old][i])
            setattr(self, f"edit_{label_text}_entry", entry_to_modify)
            entry_to_modify.pack()


        # Function for saving modifications.
        def entry_save():
            new_entry = [self.edit_0_entry.get().strip(),
                         self.edit_1_entry.get().strip(),
                         self.edit_2_entry.get().strip(),
                         self.edit_3_entry.get().strip(),]
            if not all(new_entry):
                messagebox.showerror("Error", "All fields are required.")
                return

            data = load_passwords()
            # if entry key change, deleting the oldest key.
            if new_entry[0] != old[0] and old[0] in data:
                del data[old[0]]
            data[new_entry[0]] = {
                "website": new_entry[0],
                "username": new_entry[1],
                "password": encrypt_password(self.fernet, new_entry[2])
            }
            save_passwords(data)
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

    def show_passwords(self):
        """
        Show the password cleared for the selected entry in a popup.
        """
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning("No entry selected", "Please select an entry first.")
            return

        entry_to_show = self.tree.item(selected_entry, "values")[0]
        data = load_passwords()
        tok = data.get(entry_to_show, {}).get("password", "")
        try:
            clear = decrypt_password(self.fernet, tok)
        except ValueError:
            messagebox.showerror("Error", "Cannot clear password.")
            return

        messagebox.showinfo(f"Password cleared for {entry_to_show}, {clear}")