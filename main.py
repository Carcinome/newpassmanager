"""
Here, the main code for the passwords' manager.
"""

import os
import tkinter as tk

from gui import InitiatePrimaryWindow, WindowLogin
from i18n import setup_language

# path to the primary password storage file from utils.py and gui.py.
from utils import PRIMARY_PASSWORD_FILE, create_data_dir, user_data_dir

# For packaging and defining paths.
DATA_DIR = user_data_dir()
DATA_DIR.mkdir(parents=True, exist_ok=True)

VAULT_PATH = DATA_DIR / "vault.enc"
SALT_PATH = DATA_DIR / "salt.bin"
PRIMARY_PATH = DATA_DIR / "primary_password.json"

# Auto-detect system language (default).
_, LANG = setup_language()


def main():
    """
    Entry point of the program.
    1. Check if the data directory exists.
    2. Initialize the primary password and catch the Fernet key.
    3. Launch of the first adapted GUI window (creation or login).
    """
    # 1. Data stockage directory preparation.
    create_data_dir()

    # 2. Launch the GUI.
    root = tk.Tk()
    # 3. If the primary password doesn't exist, create it.
    # If it already exists, ask for a connection.
    if not os.path.exists(PRIMARY_PASSWORD_FILE):
        InitiatePrimaryWindow(root)
    else:
        WindowLogin(root)
    root.mainloop()


# 4. This for assurance to start main() only with main.py.
if __name__ == "__main__":
    main()
