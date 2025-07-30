"""This file si for making a Graphic User Interface, for avoid command lines interface for customers."""


import tkinter as tk
from tkinter import messagebox, ttk

from cryptography.hazmat.primitives.twofactor import InvalidToken

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
        tk.Label(root, text="Enter a new primary password:").pack(pady=(20, 5))
        self.pwd_entry = tk.Entry(root, show="*", width=30)
        self.pwd_entry.pack()

        # Confirm field.
        tk.Label(root, text="Confirm password:").pack(pady=(10, 5))
        self.confirm_entry = tk.Entry(root, show="*", width=30)
        self.confirm_entry.pack()

        # "Create" button.
        tk.Button(root, text="Create", command=self.save_primary_password).pack(pady=20)


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
        self.password_entry = tk.Entry(login_root, show="*", width=30)
        self.password_entry.pack()


    def check_password(self):
        """
        A check for primary password before the access to databases.
        """
        entered_password = self.password_entry.get().strip()
        try:
            decrypt_password(self.fernet, encrypt_password(self.fernet, "test")
            )
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

    """The main window with the menu."""

    def __init__(self, primary):
        self.primary = primary
        self.primary.title("Password Manager")
        self.primary.geometry("1000x650")
        self.primary.resizable(True, True)

        # Title
        title_label = tk.Label(primary, text="welcome to your Password Manager", font=('Arial', 14))
        title_label.pack(pady=20)

        # Passwords' array
        columns = ("entry", "website", "username", "password")
        self.tree = ttk.Treeview(primary, columns=columns, show="headings")
        self.tree.heading("entry", text="Entry")
        self.tree.heading("website", text="Website")
        self.tree.heading("username", text="Username")
        self.tree.heading("password", text="Password")

        self.tree.pack(pady=10, fill="both", expand=True)

        self.load_data()

        # Buttons
        button_frame = tk.Frame(primary)
        button_frame.pack(pady=10)

        self.add_button = tk.Button(button_frame, text="Add", width=15, command=self.add_entry)
        self.add_button.pack(side="left", padx=5)

        self.edit_button = tk.Button(button_frame, text="Edit", width=15, command=self.edit_entry)
        self.edit_button.pack(side="left", padx=5)

        self.delete_button = tk.Button(button_frame, text="Delete", width=15, command=self.delete_entry)
        self.delete_button.pack(side="left", padx=5)


    def load_data(self):
        filepath = "data/passwords.json"

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


    def add_entry(self):
        # Create a new window for add an entry.
        popup = tk.Toplevel(self.primary)
        popup.title("Add Entry")
        popup.geometry("500x400")
        popup.grab_set()
        popup.resizable(True, True)

        # Field - Entry
        tk.Label(popup, text="Add Entry :").pack(pady=(10, 0))
        entryname_entry = tk.Entry(popup)
        entryname_entry.pack()

        # Field - Website/application path
        tk.Label(popup, text="Website/Application path :").pack(pady=(10, 0))
        website_entry = tk.Entry(popup)
        website_entry.pack()

        # Field - Username
        tk.Label(popup, text="Username :").pack(pady=(10, 0))
        username_entry = tk.Entry(popup)
        username_entry.pack()

        # Field - Password
        tk.Label(popup, text="Password :").pack(pady=(10, 0))
        pwd_entry = tk.Entry(popup, show="*")
        pwd_entry.pack()


        # "Save" button
        def save():
            entry = entryname_entry.get().strip()
            website = website_entry.get().strip()
            username = username_entry.get().strip()
            pwd = pwd_entry.get().strip()

            if not entry or not website or not username or not pwd:
                messagebox.showerror("Fields must be filled!", "Please fill all fields before saving.")
                return

            self.tree.insert("", "end", values=(entry, website, username, pwd))

            # Load the passwords.json file via utils.py's function.
            data = load_passwords()
            data["entry"] = {
                "website": website,
                "username": username,
                "password":pwd
            }
            save_passwords(data)
            popup.destroy()

        save_button = tk.Button(popup, text="Save", command=save)
        save_button.pack(pady=15)


    def edit_entry(self):
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning("No entry selected", "Please select an entry.")
            return

        # Take values from selected line.
        entry_old, website_old, username_old, pwd_old = self.tree.item(selected_entry, "values")

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


        # Function for saving modifications.
        def save():
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


if __name__ == "__main__":
    if not os.path.exists(PRIMARY_PASSWORD_FILE):
        root = tk.Tk()
        app = InitiatePrimaryWindow(root)
    else:
        root = tk.Tk()
        app = WindowLogin(root)

    root.mainloop()

