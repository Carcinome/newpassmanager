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
        self.pwd_entry.pack(pady=10)g

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

        # If the .json file doesn't exit, create an empty file
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
            popup.destroy()

        save_button = tk.Button(popup, text="Save", command=save)
        save_button.pack(pady=15)


    def edit_entry(self):
        selected_entry = self.tree.selection()

        if not selected_entry:
            messagebox.showwarning("No entry selected", "Please select an entry.")
            return

        # Take values from selected line
        values = self.tree.item(selected_entry, "values")
        entry_old, website_old, username_old, pwd_old = values

        # Create the popup window
        popup = tk.Toplevel(self.primary)
        popup.title("Edit entry")
        popup.geometry("500x400")
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


        # Function for saving modifications
        def save():
            entry_new = entryname_entry.get().strip()
            website_new = website_entry.get().strip()
            username_new = username_entry.get().strip()
            pwd_new = pwd_entry.get().strip()

            if not entry_new or not website_new or not username_new or not pwd_new:
                messagebox.showwarning("Fields missing!", "Please fill all fields before saving.")

            # Update selected line
            self.tree.item(selected_entry, values=(entry_new, website_new, username_new, pwd_new))
            popup.destroy()

        # "Save" button
        tk.Button(popup, text="Save", command=save).pack(pady=15)


    def delete_entry(self):
        # Take the selected element
        selected_entry = self.tree.selection()

        if not selected_entry:
            messagebox.showwarning("No entry selected", "Please select an entry.")
            return

        confirm = messagebox.askyesno("Confirm deleting", "Would you really want to delete this entry?")

        if confirm:
            self.tree.delete(selected_entry)


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


if __name__ == "__main__":
    if not os.path.exists(PRIMARY_PASSWORD_FILE):
        root = tk.Tk()
        app = InitiatePrimaryWindow(root)
    else:
        root = tk.Tk()
        app = WindowLogin(root)

    root.mainloop()

