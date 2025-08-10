"""Here, the main code for the passwords' manager."""

import os
import tkinter as tk

# path to the primary password storage file from utils.py and gui.py.
from utils import create_data_dir, PRIMARY_PASSWORD_FILE
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

    # 2. Launch the GUI.
    root = tk.Tk()
    # 3. If the primary password doesn't exist, create it. If it already exists, ask for connection.
    if not os.path.exists(PRIMARY_PASSWORD_FILE):
        app = InitiatePrimaryWindow(root)
    else:
        app = WindowLogin(root)
    root.mainloop()

# 4. This for assurance to start main() only with main.py.
if __name__ == "__main__":
    main()