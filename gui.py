"""This file si for making a Graphic User Interface, for avoid command lines interface for customers."""

import json
import os
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk


PRIMARY_PASSWORD_FILE = "data/primary_password.json"


class InitiatePrimaryWindow:
    """For creating a primary password if it doesn't exist."""
    def __init__(self, primary):
        self.primary = primary
        self.primary.title("Create a primary password")
        self.primary.geometry("400x300")
        self.primary.resizable(False, False)

        # Main text
        self.label = tk.Label(primary, text="Create your primary password", font=("Arial", 15))
        self.label.pack(pady=10)

        # Field 1 - password
        self.pwd_entry = tk.Entry(primary, show="*", width=40)
        self.pwd_entry.pack(pady=10)

        # Field 2 - confirmation
        self.confirm_entry = tk.Entry(primary, show="*", width=40)
        self.confirm_entry.pack(pady=10)

        # "Save" button
        self.save_button = tk.Button(primary, text="Save", command=self.save_primary_password)
        self.save_button.pack(pady=15)

    def save_primary_password(self):
        """For saving primary password."""
        password = self.pwd_entry.get()
        password_confirmation = self.confirm_entry.get()

        if not password or not password_confirmation:
            messagebox.showerror("Error", "All fields are required.")
            return

        if password != password_confirmation:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        os.makedirs("data", exist_ok=True) # For creating the data folder if it doesn't exist.

        with open(PRIMARY_PASSWORD_FILE, "w") as f:
            json.dump({"primary_password": password},f)

        messagebox.showinfo("Success", "Primary password saved.")
        self.primary.destroy() # close the window

        # Open the connection window
        save_primary_pwd_root = tk.Tk()
        save_primary_pwd_app = WindowLogin(save_primary_pwd_root)
        save_primary_pwd_root.mainloop()


class WindowLogin:
    """Login screen."""
    def __init__(self, primary):
        self.primary = primary
        self.primary.title("Connection - Password manager")
        self.primary.geometry("400x300")
        self.primary.resizable(False, False)

        # Main text
        self.label = tk.Label(primary, text="Enter your primary password :", font=("Arial", 15))
        self.label.pack(pady=20)

        # Password entry (hide with *)
        self.password_entry = tk.Entry(primary, show="*", width=20)
        self.password_entry.pack()

        # "Connect" button
        self.login_button = (tk.Button(primary, text="Connect", command=self.check_password))
        self.login_button.pack(pady=20)

    def check_password(self):
        """A check for primary password before the access to databases."""
        entered_password = self.password_entry.get()

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

        # Buttons
        button_frame = tk.Frame(primary)
        button_frame.pack(pady=10)

        self.add_button = tk.Button(button_frame, text="Add", width=15, command=self.add_entry)
        self.add_button.pack(side="left", padx=5)

        self.edit_button = tk.Button(button_frame, text="Edit", width=15, command=self.edit_entry)
        self.edit_button.pack(side="left", padx=5)

        self.delete_button = tk.Button(button_frame, text="Delete", width=15, command=self.delete_entry)
        self.delete_button.pack(side="left", padx=5)

    def add_entry(self):
        # Create a new window for add an entry
        popup = tk.Toplevel(self.primary)
        popup.title("Add Entry")
        popup.geometry("500x400")
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

        # Field - password
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
            popup.destroy()

        save_button = tk.Button(popup, text="Save", command=save)
        save_button.pack(pady=15)


    def edit_entry(self):
        pass # To define later

    def delete_entry(self):
        pass # To define later



if __name__ == "__main__":
    if not os.path.exists(PRIMARY_PASSWORD_FILE):
        root = tk.Tk()
        app = InitiatePrimaryWindow(root)
    else:
        root = tk.Tk()
        app = WindowLogin(root)

    root.mainloop()

