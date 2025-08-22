"""This file si for making a Graphic User Interface, for avoid command lines interface for customers."""


import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
import logging, os


from cryptography.fernet import InvalidToken

from utils import (
    write_primary_verifier,
    verify_primary_password_and_get_key,
)

from src.vault import (load_encrypted_vault,
                       save_encrypted_vault,
                       Vault,
                       Entry
)

from i18n import _

VAULT_PATH = Path("data") / "vault.enc"
LOG_PATH = os.path.join("data", "app.log")
# _, LANG = setup_language() # harmless if called twice; ensures _() is available.

# Logging users errors.
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
logger = logging.getLogger("gui")

def show_error(title: str, message: str, details: str | None = None):
    """
    Display a uniformed error message.
    - title: short.
    - message: clear for user.
    - details: optional, on a second line more technic
    - logging errors for programmer.
    """
    if details:
        logging.error("%s - %s - %s", title, message, details)
        messagebox.showerror(title, f"{message}\n\nDetails: \n{details}")
    else:
        logging.error("%s - %s", title, message)
        messagebox.showerror(title, message)

class InitiatePrimaryWindow:
    """
    For creating a primary password if it doesn't exist.
    Display two fields (password and confirmation) and one 'create' button.
    """
    def __init__(self, primary):

        self.primary = primary

        # Main text.
        self.primary.title_("Create primary password")
        self.primary.geometry("400x300")
        self.primary.resizable(False, False)

        # Password field.
        tk.Label(self.primary, text=_("Enter a new primary password:")).pack(pady=(20, 5))
        self.pwd_entry = tk.Entry(self.primary, show="*", width=30)
        self.pwd_entry.pack()

        # Confirm field.
        tk.Label(self.primary, text=_("Confirm password:")).pack(pady=(10, 5))
        self.confirm_entry = tk.Entry(self.primary, show="*", width=30)
        self.confirm_entry.pack()

        # "Create" button.
        tk.Button(self.primary, text=_("Create"), command=self.save_primary_password).pack(pady=20)

    def save_primary_password(self):
        """
        For saving primary password.
        """
        password = (self.pwd_entry.get() or "").strip()
        password_confirmation = (self.confirm_entry.get() or "").strip()

        if not password or not password_confirmation:
            messagebox.showerror(_("Error"), _("All fields are required."))
            return

        if password != password_confirmation:
            messagebox.showerror(_("Error"), _("Passwords do not match."))
            return

        try:
            write_primary_verifier(password)
        except ValueError as err:
            messagebox.showerror(_("Error"), _(f"Could not save primary password : {err}."))
            return

        messagebox.showinfo(_("Success"), _("Primary password saved."))
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
        self.vault = None

        self.login_root.title(_("Connection - Password manager"))
        self.login_root.geometry("300x200")
        self.login_root.resizable(False, False)

        # Main text
        tk.Label(login_root, text=_("Enter your primary password :")).pack(pady=(30, 5))
        self.password_entry = tk.Entry(login_root, show="*", width=30); self.password_entry.pack()
        tk.Button(login_root, text=_("Login"), command=self.check_password).pack(pady=20)

    def check_password(self):
        """
        A check for the primary password before the access to databases.
        """
        entered_password = (self.password_entry.get() or "").strip()

        if not entered_password:
            messagebox.showwarning(_("Missing password"), _("Please type your primary password."))
            return

        try:
            self.fernet = verify_primary_password_and_get_key(entered_password)
        except FileNotFoundError:
            show_error(
                _("No primary password"),
                _("No primary password found. Please create one first.")
            )
            return
        except InvalidToken:
            show_error(
                _("Invalid password"),
                _("The primary password entered is incorrect.")
            )
            return
        except Exception as exc:
            show_error(
                _("Unexpected error"),
                _("An unexpected error occurred while checking your password."),
            details=str(exc)
            )
            return

        try:
            self.vault = load_encrypted_vault(self.fernet, str(VAULT_PATH))
        except FileNotFoundError:
            self.vault = Vault()
        except InvalidToken:
            show_error(
                _("Vault error"),
                _("The vault can't be decrypted with this key or is corrupted.\n"),
                _("Make sure you type the correct primary password."),
                details=str(VAULT_PATH)
            )
            return
        except PermissionError as exc:
            show_error(
                _("Permission denied"),
                _("The application can't read the vault file. Please check file permissions."),
                details=str(exc)
            )
            return
        except Exception as exc:
            show_error(
                _("Unexpected error"),
                _("An unexpected error occurred while reading the vault."),
                details=str(exc)
            )
            return

        messagebox.showinfo(_("Success"), _("Login successful."))
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
        self.fernet = fernet            # Fernet key (already validated on login).
        self.vault = vault              # Vault in RAM (cleared).
        self.vault_path = vault_path    # Path of the encrypted vault.
        self.clipboard_timeout_ms = 30_000
        self.show_timeout_ms = 15_000
        self.remask_jobs = {}

        self.primary_main.title(_("Password manager"))
        self.primary_main.geometry("1000x800")
        self.primary_main.resizable(True, True)



        # Array - Treeview.
        columns = (_("entry"), _("website or application path"), _("username"), _("password"))
        self.tree = ttk.Treeview(primary_main, columns=columns, show="headings")
        for c, text in zip(columns, (_("entry"), _("website or application path"), _("username"), _("password"))):
            self.tree.heading(c, text=text)
            self.tree.column(c, width=150)
        self.tree.pack(fill="both", expand=True, pady=(10, 0))

        self.status_var = tk.StringVar(value="")
        status = tk.Label(self.primary_main, textvariable=self.status_var, anchor="w")
        status.pack(fill="x", padx=8, pady=(2, 6))

        # Buttons
        button_frame = tk.Frame(primary_main)
        button_frame.pack(pady=10)

        # Menu.
        menubar = tk.Menu(self.primary_main)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label=_("Sticky notes"), command=self.show_help)
        help_menu.add_command(label=_("About"), command=self.show_about)

        menubar.add_cascade(label=_("Help"), menu=help_menu)
        self.primary_main.config(menu=menubar)

        self.primary_main.bind_all("<Control-h>", lambda e: self.show_help())
        self.primary_main.bind_all("<Control-H>", lambda e: self.show_help())
        self.primary_main.bind_all("<F1>",      lambda e: self.show_help())

        tk.Button(button_frame, text=_("Add"), command=self.add_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Edit"), command=self.edit_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Delete"), command=self.delete_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Show"), command=self.show_password).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Copy"), command=self.copy_password).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Hide all"), command=self.hide_all_passwords).pack(side="left", padx=10)

        self.load_data()

    def load_data(self):
        """
        Load the passwords crypted and display:
                - 3 first columns cleared
                - The 'password' column on masked form (******).
        """
        # Clean the Treeview.
        self.tree.delete(*self.tree.get_children())
        # Read a snapshot dict from the vault.
        data = self.vault.to_dict_entry()
        # For all entries, decrypt and mask datas.
        for entry, info in data.items():
            website = info.get("website", "")
            username = info.get("username", "")
            cleared_password = info.get("password", "")
            masked_password = self.mask_for(cleared_password)
            self.tree.insert("", "end", values=(entry, website, username, masked_password))

    def add_entry(self):
        """
        Open a popup for entering a new entry.
        Write a new entry name, website or application path, username and password.
        Finally, save it and reload the array.
        """
        popup = tk.Toplevel(self.primary_main)
        popup.title(_("Add new entry"))
        popup.geometry("600x400")
        popup.grab_set()

        # Fields.
        tk.Label(popup, text=_("Entry :")).pack(pady=(30, 5))
        new_entry_entry = tk.Entry(popup); new_entry_entry.pack()
        tk.Label(popup, text=_("Website or application path :")).pack(pady=(30, 5))
        new_website_entry = tk.Entry(popup); new_website_entry.pack()
        tk.Label(popup, text=_("Username :")).pack(pady=(30, 5))
        new_username_entry = tk.Entry(popup); new_username_entry.pack()
        tk.Label(popup, text=_("Password :")).pack(pady=(30, 5))
        new_password_entry = tk.Entry(popup, show="*"); new_password_entry.pack()

        # "Save" button.
        def save():
            entry       = new_entry_entry.get().strip()
            website     = new_website_entry.get().strip()
            username    = new_username_entry.get().strip()
            pwd         = new_password_entry.get().strip()

            if not (entry and website and username and pwd):
                messagebox.showerror(_("Fields must be filled!"), _("Please fill all fields before saving."))
                return
            # Construct the Entry object (cleared in RAM).
            clear_memory_obj = Entry(name=entry, website=website, username=username, password=pwd)

            # Add the Entry object to the vault (start the rule "no double").
            try:
                self.vault.add_vault_entry(clear_memory_obj)
            except ValueError as err:
                show_error(
                    _("Duplicate entry"),
                    str(err)
                )
                return
            except Exception as exc:
                show_error(
                    _("Unexpected error"),
                    _("Couldn't add the entry."),
                    details=str(exc)
                )
                return

            # Crypted save from the entire vault.
            try:
                save_encrypted_vault(self.vault, self.fernet, self.vault_path)
            except PermissionError as exc:
                show_error(
                    _("Permission denied"),
                    _("Can't write the encrypted vault file."),
                    details=str(exc)
                )
                return
            except Exception as exc:
                show_error(
                    _("Unexpected error"),
                    _("Couldn't save the encrypted vault."),
                    details=str(exc)
                )
                return

            popup.destroy()
            self.load_data()

        tk.Button(popup, text=_("Save"), command=save).pack(pady=(30, 5))

    def edit_entry(self):
        """
        Open a popup for editing a selected entry.
        Finally, update the passwords.json file and reload the array.
        """
        selected_entry = self.tree.selection()

        if not selected_entry:
            messagebox.showwarning(_("No entry selected"), _("Please select an entry."))
            return

        # Take values from the selected line.
        entry_old, website_old, username_old, pwd_old = self.tree.item(selected_entry, "values")
        # Popup creation.
        popup = tk.Toplevel(self.primary_main)
        popup.title(_("Edit entry"))
        popup.geometry("700x500")
        popup.grab_set()

        # Fields autoloaded.
        tk.Label(popup, text=_("Entry :")).pack(pady=(30, 5))
        entry_input = tk.Entry(popup)
        entry_input.insert(0, entry_old)
        entry_input.pack()

        tk.Label(popup, text="_(Website or application path :").pack(pady=(30, 5))
        website_input = tk.Entry(popup)
        website_input.insert(0, website_old)
        website_input.pack()

        tk.Label(popup, text=_("Username :")).pack(pady=(30, 5))
        username_input = tk.Entry(popup)
        username_input.insert(0, username_old)
        username_input.pack()

        tk.Label(popup, text=_("Password :")).pack(pady=(30, 5))
        password_input = tk.Entry(popup, show="*")
        password_input.insert(0, pwd_old)
        password_input.pack()

        # Function for saving modifications.
        def entry_save():
            # Read the new fields.
            entry_new       = entry_input.get().strip()
            website_new     = website_input.get().strip()
            username_new    = username_input.get().strip()
            pwd_new         = password_input.get().strip()

            if entry_new != entry_old:
                # If the name of the entry change.
                try:
                    self.vault.delete_vault_entry(entry_old)
                    self.vault.add(Entry(name=entry_new, website=website_new, username=username_new, password=pwd_new))
                except KeyError as err:
                    show_error(
                        _("Entry not found"),
                        _(f"Cannot edit {err}")
                    )
                    return
                except ValueError as err:
                    show_error(
                        _("Duplicate entry"),
                        str(err))
                    return
            else:
                # If the name of the entry doesn't change, just a field update.
                try:
                    self.vault.update_vault_entry(entry_old,
                                                  website=website_new,
                                                  username=username_new,
                                                  password=pwd_new)
                except KeyError as err:
                    show_error(
                        _("Entry not found"),
                        _(f"Cannot edit {err}"))
                    return

            try:
                save_encrypted_vault(self.vault, self.fernet, self.vault_path)
            except PermissionError as exc:
                show_error(
                    _("Permission denied"),
                    _("Can't write the encrypted vault file."),
                    details=str(exc)
                )
                return
            except Exception as exc:
                show_error(
                    _("Unexpected error"),
                    _("Couldn't save the encrypted vault."),
                    details=str(exc)
                )
                return

        tk.Button(popup, text=_("Update entry"), command=entry_save).pack(pady=20)

    def delete_entry(self):
        """
        Delete a selected entry.
        """
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning(_("No entry selected"), _("Please select an entry first."))
            return

        entry_to_delete = self.tree.item(selected_entry, "values")[0]

        if not messagebox.askyesno(_("Please confirm deletion"), _(f"Deleting {entry_to_delete}?")):
            return

        try:
            self.vault.delete_vault_entry(entry_to_delete)
        except KeyError:
            show_error(
                _("entry not found"),
                _(f"Entry {entry_to_delete} not found."))
            return
        except Exception as exc:
            show_error(
                _("Unexpected error"),
                _("Couldn't delete the entry."),
                details=str(exc)
            )
            return

        try:
            save_encrypted_vault(self.vault, self.fernet, self.vault_path)
        except PermissionError as exc:
            show_error(
                _("Permission denied"),
                _("Can't write the encrypted vault file."),
                details=str(exc)
            )
            return
        except Exception as exc:
            show_error(
                _("Unexpected error"),
                _("Couldn't save the encrypted vault."),
                details=str(exc)
            )
            return

        self.load_data()

    def show_password(self):
        """
        Show the password cleared for the selected entry in a popup.
        """
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning(_("No entry selected"), _("Please select an entry first."))
            return

            # Unic ID of the selected line.
        item_id = selected_entry[0]
        entry_to_show = self.tree.item(item_id, "values")[0]
        entry_to_clear = self.vault.get_vault_entry(entry_to_show)

        if not entry_to_clear:
            messagebox.showerror(_("Error"), _(f"Entry {entry_to_show} not found."))
            return

        clear_pwd = entry_to_clear.password
        mask = self.mask_for(clear_pwd)

        self.cancel_remask_if_any(item_id)

        # Display the cleared password in the cell.
        try:
            self.tree.set(item_id, "password", clear_pwd)
        except tk.TclError:
            return
        self.status_var.set(_(f"Password for {entry_to_show} is shown for {self.show_timeout_ms}ms."))

        # Reprogramming of masking.
        def hide_again():
            try:
                self.tree.set(item_id, "password", mask)
            except tk.TclError:
                pass # In case of line disappear.
            if self.status_var.get().startswith("Password displayed"):
                self.status_var.set("")
            self.remask_jobs.pop(item_id, None)

        after_id = self.primary_main.after(self.show_timeout_ms, hide_again)
        self.remask_jobs[item_id] = after_id


    def copy_password(self):
        """
        Copy the password to the clipboard from the selected line.
        """
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning(_("No entry selected"), _("Please select a line first."))
            return

        entry_to_copy = self.tree.item(selected_entry[0], "values")[0]
        entry_to_get = self.vault.get_vault_entry(entry_to_copy)

        if not entry_to_get:
            messagebox.showerror(_("Error"), _(f"Entry '{entry_to_copy}' not found."))
            return

        clear_pwd = entry_to_get.password # In the RAM, cleared, just for GUI.

        # Copy the password in the Tkinter's clipboard.
        # Remplace the copied data and add the password after.
        self.primary_main.clipboard_clear()
        self.primary_main.clipboard_append(clear_pwd)
        # Notify the user.
        messagebox.showinfo(_("Password copied to clipboard"), _(f"Password for '{entry_to_copy}' is copied to clipboard."))
        # Auto clear clipboard.
        self.schedule_clipboard_clear()

    # Enhanced security: clear the clipboard.
    def schedule_clipboard_clear(self):
        """
        Clear the clipboard after select.clipboard_timeout_ms.
        """
        def clear_clipboard():
            try:
                self.primary_main.clipboard_clear()
            except tk.TclError:
                pass
        self.primary_main.after(self.clipboard_timeout_ms, clear_clipboard)

    def mask_for(self, clear_pwd: str) -> str:
        """
        For calculating a masked version of a password.
        """
        return "•" * max(35, len(clear_pwd))

    def cancel_remask_if_any(self, item_id):
        """
        Cancel a timer for remasking for the selected line, if it presents.
        """
        job = self.remask_jobs.pop(item_id, None)
        if job is not None:
            try:
                self.primary_main.after_cancel(job)
            except Exception:
                pass
    
    def hide_all_passwords(self):
        """
        Automatically hide all password entries and cancel all timers.
        """
        for item_id in self.tree.get_children():
            values = list(self.tree.item(item_id, "values")) # values = [entry, website, username, password]
            name = values[0]
            entry = self.vault.get_vault_entry(name)
            if entry:
                values[3] = self.mask_for(entry.password)
                try:
                    self.tree.item(item_id, values=values)
                except tk.TclError:
                    pass
            self.cancel_remask_if_any(item_id)
        self.status_var.set("")

    def show_help(self):
        """
        Show an information window about the application and their functionalities.
        """
        top = tk.Toplevel(self.primary_main)
        top.title(_("Sticky note"))
        top.geometry("620x420")
        top.resizable(True, True)

        txt = tk.Text(top, width=80, height=18, wrap="word")
        txt.pack(fill="both", expand=True, padx=10, pady=10)

        content = (_(
            "• The vault is crypted (Fernet) on data/vault.enc.\n"
            "• The passwords are in clean text in RAM only when the execution of the program.\n"
            "• 'Show' displays the password in the selected cell, and remask it automatically.\n"
            "• 'Copy' copies the password to the clipboard and clean it after a delay.\n"
            "• 'Hide all' hides all passwords and cancels all timers.\n"
            "• Saving the file in data/vault.enc regularity.\n"
            "• Salt is in data/salt.bin\n"
            "• A primary password is essential.\n"
            "• All modifications (GRUD) is persistant with save_encrypted_vault().\n"
            "• In case of error 'Vault is corrupted', please verify the primary password and the files.\n"
        ))
        txt.insert("1.0", content)
        txt.configure(state="disabled")

    def show_about(self):
        messagebox.showinfo(_(
            "About"),
            _("Password manager\n"
            "Vault crypted with Fernet (cryptography).\n"
            "Version : 0.2 (Phase 2)\n"
            "Author : Clément 'Carcinome' Aicardi"
        ))






