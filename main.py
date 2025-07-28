"""Here, the main code for the passwords' manager."""

import os
import tkinter as tk

# path to the primary password storage file from utils.py and gui.py.
from utils import create_data_dir, init_storage_primary_password, PRIMARY_PASSWORD_FILE
from gui import InitiatePrimaryWindow, WindowLogin


def main():
    """
    Entry point of the program.
    1. Check if the data directory exists.
    2. Initialize the primary password and catch the Fernet key.
    3. Launch of the first adapted GUI window (creation or login).
    """
# 1. Data stockage directory preparation.
create_data_dir()


# 2. Initialize/verify the primary password.
# Return the Fernet object for crypt/decrypt.
fernet = init_storage_primary_password()


# 3. Launch the GUI.
root = tk.Tk()
# If the primary_password.json file doesn't exist, creat it. If it is, log in.
if not os.path.exists(PRIMARY_PASSWORD_FILE):
    gui_password_app = InitiatePrimaryWindow(root)
else:
    gui_password_app = WindowLogin(root)
root.mainloop()


# 4. This for assurance to start main() only with main.py.
if __name__ == "__main__":
    main()