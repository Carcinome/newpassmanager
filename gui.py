"""This file si for making a Graphic User Interface, for avoid command lines interface for customers."""

import json
import os
import tkinter as tk
from tkinter import messagebox


MASTER_PASSWORD_FILE = "data/master.json"


class WindowLogin:
    """Login screen."""
    def __init__(self, master):
        self.master = master
        self.master.title("Connection - Password manager")
        self.master.geometry("400x300")
        self.master.resizable(False, False)

        # Main text
        self.label = tk.Label(master, text="Enter your master password :", font=("Arial", 20))
        self.label.pack(pady=20)

        # Password entry (hide with *)
        self.password_entry = tk.Entry(master, show="*", width=20)
        self.password_entry.pack()

        # "Connect" button
        self.login_button = (tk.Button(master, text="Connect", command=self.check_password))
        self.login_button.pack(pady=20)

    def check_password(self):
        """A  check for master password before the access to databases."""
        entered_password = self.password_entry.get()

        if not os.path.exists(MASTER_PASSWORD_FILE):
            messagebox.showerror("Error", "master password file not found.")
            return

        with open(MASTER_PASSWORD_FILE, "r") as f:
            data = json.load(f)

        if entered_password == data.get("master_password"):
            messagebox.showinfo("Success", "Connection approved.")
            self.master.destroy() # close the window
            # Here for open main interface later
        else:
            messagebox.showerror("Error", "Wrong password.")


if __name__ == "__main__":
    root = tk.Tk()
    app = WindowLogin(root)
    root.mainloop()

