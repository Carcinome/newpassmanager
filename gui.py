"""This file si for making a Graphic User Interface, for avoid command lines interface for customers."""


import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
import logging, os, string, secrets


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
        self.login_root.geometry("300x150")
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

        # For search.
        search_frame = ttk.Frame(self.primary_main)
        search_frame.pack(fill="x", padx=10, pady=5)

        self.search_var = tk.StringVar(value="")

        def on_search_var_changed(*_):
            self.schedule_live_search()

        # Trace on writing: callback whenever the text changes.
        self.search_var.trace_add("write", on_search_var_changed)

        ttk.Label(search_frame, text=_("Search :")).pack(side="left", padx=(0, 6))
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side="left", expand=True, fill="x")

        self.tag_filter_var = tk.StringVar(value="All tags")
        self.tag_filter = ttk.Combobox(
            search_frame,
            textvariable=self.tag_filter_var,
            state="readonly",
            width=18
        )
        self.tag_filter.pack(side="left", padx=(6, 0))
        # When a user picks a tag, re-run the live search immediately.
        self.tag_filter.bind("<<ComboboxSelected>>", lambda e: self.apply_live_search())

        # search_button = ttk.Button(search_frame, text=_("Search"), command=self.search_entries)
        # search_button.pack(side="left", padx=(5, 0))

        reset_button = ttk.Button(search_frame, text=_("Reset"), command=self.reset_search)
        reset_button.pack(side="left", padx=(5, 0))

        # Debounce job id for live search.
        self.search_job = None
        # Debounce delay in milliseconds.
        self.search_debounce_ms = 200

        # Array - Treeview.
        columns = ("Entry", "Tags", "Website or application path", "Username", "Password")
        self.tree = ttk.Treeview(primary_main, columns=columns, show="headings", height=16)

        column_widths = {
            "Entry": 150,
            "Tags": 120,
            "Website or application path": 340,
            "Username": 180,
            "Password": 160,
        }
        column_stretch = {
            "Entry": False,
            "Tags": False,
            "Website or application path": True,
            "Username": False,
            "Password": False,
        }

        for c, text in zip(
            columns,
            (_("Entry"), _("Tags"), _("Website or application path"), _("Username"), _("Password"))
        ):
            self.tree.heading(c, text=text, command=lambda col=c: self.sort_by_column(col))


            self.tree.column(
                c,
                width=column_widths.get(c, 150),
                stretch=column_stretch.get(c, False),
                anchor="w"
            )

        self.tree.pack(fill="both", expand=True, pady=(10, 0))
        self.status_var = tk.StringVar(value="")
        status = tk.Label(self.primary_main, textvariable=self.status_var, anchor="w")
        status.pack(fill="x", padx=8, pady=(2, 6))

        # Sort state: remember the ascending/descending order of the column. Works by column's id.
        self.sort_reverse = {
            "Entry": False,
            "Tags": False,
            "Website or application path": False,
            "Username": False,
            "Password": False,
        }

        # Helpful mapping: column id -> index in values tuple.
        self.col_index = {
            "Entry": 0,
            "Tags": 1,
            "Website or application path": 2,
            "Username": 3,
            "Password": 4,
        }

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
        self.tree.bind("<Double-1>", self.on_row_double_click)

        tk.Button(button_frame, text=_("Add"), command=self.add_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Edit"), command=self.edit_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Delete"), command=self.delete_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Show"), command=self.show_password).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Copy"), command=self.copy_password).pack(side="left", padx=10)
        tk.Button(button_frame, text=_("Hide all"), command=self.hide_all_passwords).pack(side="left", padx=10)

        self.setup_shortcuts()
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
            tags_list = info.get("tags", []) or []
            tags_text = ", ".join(tags_list)
            website = info.get("website", "")
            username = info.get("username", "")
            cleared_password = info.get("password", "")
            masked_password = self.mask_for(cleared_password)
            self.tree.insert("", "end", values=(entry, tags_text, website, username, masked_password))

        # refresh tag filter options after (re)loading.
        all_tags = self.collect_all_tags() or []
        values = ["All tags"] + all_tags
        self.tag_filter["values"] = values
        current = self.tag_filter_var.get()
        if current not in values:
            self.tag_filter_var.set("All tags")

    def add_entry(self):
        """
        Open a popup for entering a new entry.
        Write a new entry name, website or application path, username and password.
        Tags is optional.
        Finally, save it and reload the array.
        """
        popup = tk.Toplevel(self.primary_main)
        popup.title(_("Add new entry"))
        popup.geometry("300x500")
        popup.grab_set()

        # Fields.
        tk.Label(popup, text=_("Entry :")).pack(pady=(30, 5))
        new_entry_entry = tk.Entry(popup); new_entry_entry.pack()
        tk.Label(popup, text=_("Tags :")).pack(pady=(30, 5))
        new_tag_entry = tk.Entry(popup); new_tag_entry.pack()
        tk.Label(popup, text=_("Website or application path :")).pack(pady=(30, 5))
        new_website_entry = tk.Entry(popup); new_website_entry.pack()
        tk.Label(popup, text=_("Username :")).pack(pady=(30, 5))
        new_username_entry = tk.Entry(popup); new_username_entry.pack()
        tk.Label(popup, text=_("Password :")).pack(pady=(30, 5))
        new_password_entry = tk.Entry(popup, show="*"); new_password_entry.pack()
        ttk.Button(popup, text=_("Generate password"),
                   command=lambda: self.open_password_generator(popup, new_password_entry)).pack(pady=(5, 10))

        # "Save" button.
        def save():
            entry       = new_entry_entry.get().strip()
            raw_tags    = new_tag_entry.get().strip()
            tag_list    = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []
            website     = new_website_entry.get().strip()
            username    = new_username_entry.get().strip()
            pwd         = new_password_entry.get().strip()

            if not (entry and website and username and pwd):
                messagebox.showerror(_("Fields must be filled!"), _("Please fill all fields before saving."))
                return
            # Construct the Entry object (cleared in RAM).
            clear_memory_obj = Entry(name=entry, tags=tag_list, website=website, username=username, password=pwd)

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
        popup.bind("<Return>", lambda e: save())
        popup.bind("<Escape>", lambda e: popup.destroy())

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
        entry_old, tag_old, website_old, username_old, pwd_old = self.tree.item(selected_entry, "values")
        # Popup creation.
        popup = tk.Toplevel(self.primary_main)
        popup.title(_("Edit entry"))
        popup.geometry("300x500")
        popup.grab_set()

        # Fields autoloaded.
        tk.Label(popup, text=_("Entry :")).pack(pady=(30, 5))
        entry_input = tk.Entry(popup)
        entry_input.insert(0, entry_old)
        entry_input.pack()

        tk.Label(popup, text=_("Tags :")).pack(pady=(30, 5))
        tag_input = tk.Entry(popup)
        tag_input.insert(0, tag_old)
        tag_input.pack()

        tk.Label(popup, text=_("Website or application path :")).pack(pady=(30, 5))
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

        tk.Button(popup, text=_("Generate password"),
                  command=lambda: self.open_password_generator(popup, password_input)).pack(pady=(5, 10))

        # Function for saving modifications.
        def entry_save():
            # Read the new fields.
            entry_new       = entry_input.get().strip()
            raw_tags_new    = tag_input.get().strip()
            tags_list_new    = [t.strip() for t in raw_tags_new.split(",") if t.strip()] if raw_tags_new else []
            website_new     = website_input.get().strip()
            username_new    = username_input.get().strip()
            pwd_new         = password_input.get().strip()

            if entry_new != entry_old:
                # If the name of the entry change.
                try:
                    self.vault.delete_vault_entry(entry_old)
                    self.vault.add(Entry(name=entry_new, tags=tags_list_new, website=website_new, username=username_new, password=pwd_new))
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
                                                  tags=tags_list_new,
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

            popup.destroy()
            self.load_data()

        tk.Button(popup, text=_("Update entry"), command=entry_save).pack(pady=20)
        popup.bind("<Return>", lambda e: entry_save())
        popup.bind("<Escape>", lambda e: popup.destroy())


    def delete_entry(self):
        """
        Delete a selected entry.
        """
        selected_entry = self.tree.selection()
        if not selected_entry:
            messagebox.showwarning(_("No entry selected"), _("Please select an entry first."))
            return

        entry_to_delete = self.tree.item(selected_entry[0], "values")[0]

        deleting_confirmation = messagebox.askyesno(
            _("Please confirm deletion"),
            _(f"Deleting {entry_to_delete}?\n"
            "This action can't be undone.")
        )
        if not deleting_confirmation:
            self.set_status(_("Deletion cancelled."))
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
        self.apply_live_search()
        self.set_status(_(f"Entry {entry_to_delete} deleted."))

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
            self.tree.set(item_id, "Password", clear_pwd)
        except tk.TclError:
            return
        self.status_var.set(_(f"Password for {entry_to_show} is shown for {self.show_timeout_ms}ms."))

        # Reprogramming of masking.
        def hide_again():
            try:
                self.tree.set(item_id, "Password", mask)
            except tk.TclError:
                pass # In case of line disappear.
            if self.status_var.get().startswith("Password displayed"):
                self.status_var.set("")
            self.remask_jobs.pop(item_id, None)

        after_id = self.primary_main.after(self.show_timeout_ms, hide_again)
        self.remask_jobs[item_id] = after_id
        self.set_status(_(f"Password displayed for {self.show_timeout_ms}ms."))


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
        self.set_status(_(f"Password for '{entry_to_copy}' copied to clipboard"))

    def on_row_double_click(self, event):
        """
        Double-clik on a row copies the password to the clipboard.
        """
        item_id = self.tree.identify_row(event.y)
        if not item_id: # Clicked on the empty space or header.
            return

        name = self.tree.item(item_id, "values")[0]
        entry = self.vault.get_vault_entry(name)
        if not entry:
            show_error(
                _("Entry not found"),
                _(f"Entry '{name}' not found.")
            )
            return

        clear_pwd = entry.password
        # Copy the clipboard (same behavior as a copy button).
        try:
            self.primary_main.clipboard_clear()
            self.primary_main.clipboard_append(clear_pwd)
        except tk.TclError:
            show_error(
                _("Error"),
                _(f"Couldn't copy the password to clipboard.")
            )
            return

        self.schedule_clipboard_clear()
        self.set_status(_(f"Password for '{name}' copied to clipboard"))


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
                values[4] = self.mask_for(entry.password)
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

    def set_status(self, text: str, timout_ms: int = 3000):
        """Show a temporary status message in the bottom bar.
        """
        self.status_var.set(text)

        def clear():
            # Clear only if it wasn't updated by something else since.
            if self.status_var.get()  == text:
                self.status_var.set("")
        self.primary_main.after(timout_ms, clear)

    def search_entries(self):
        """
        Filter the Treeview by search string (in name, website or username).
        """
        query = self.search_var.get().strip().lower()
        if not query:
            self.set_status(_("Please enter a search term."))
            return

        # Clear the tree.
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Filter entries.
        entries = self.vault.iter_vault_entries()
        for entry in entries():
            if (query in entry.name.lower() or
                query in entry.website.lower() or
                query in entry.username.lower()):
                tag_text = ", ".join(entry.tags or [])
                masked = self.mask_for(entry.password)
                self.tree.insert("", "end", values=(entry.name, tag_text, entry.website, entry.username, masked))
        self.set_status(_(f"Results for '{query}"))

    def reset_search(self):
        """
        Reset the search field and reload all entries.
        """
        # Cancel pending live-search job if any.
        if self.search_job is not None:
            try:
                self.primary_main.after_cancel(self.search_job)
            except Exception:
                pass
            self.search_job = None

        self.search_var.set("")
        self.load_data()
        self.set_status(_("Search cleared. Showing all entries."))


    def schedule_live_search(self):
        """
        Debounce live search: schedule apply after a short delay.
        """
        if self.search_job is not None:
            try:
                self.primary_main.after_cancel(self.search_job)
            except Exception:
                pass
            self.search_job = None

        # Schedule a fresh job.
        self.search_job = self.primary_main.after(
            self.search_debounce_ms, self.apply_live_search
        )

    def apply_live_search(self):
        """
        Apply the current search filter immediately.
        """
        self.search_job = None
        query = (self.search_var.get() or "").strip().lower()
        selected_tag = (self.tag_filter_var.get() or "All tags").strip()
        tag_filter_active = (selected_tag != "All tags")
        selected_tag_lc = selected_tag.lower()

        # Clear the table.
        self.tree.delete(*self.tree.get_children())

        entries = self.vault.iter_vault_entries()

        def matches(entry) -> bool:
            # 1. Text query in name, website, username or tag.
            if query:
                in_text = (
                    query in entry.name.lower()
                    or query in entry.website.lower()
                    or query in entry.username.lower()
                    or any(query in (t or "").lower() for t in (entry.tags or []))
                )
                if not in_text:
                    return False

            # 2. Tag filter (exact tag, case-insensitive).
            if tag_filter_active:
                if not any(selected_tag_lc == (t or "").lower() for t in (entry.tags or [])):
                    return False

            return True

        # Rebuild the tree with the filtered entries.
        for entry in entries:
            if matches(entry):
                masked = self.mask_for(entry.password)
                tags_text = ", ".join(entry.tags or [])
                self.tree.insert("", "end", values=(entry.name, tags_text, entry.website, entry.username, masked))

        # Status.
        if query or tag_filter_active:
            self.set_status(_(f"Search results for '{query}'"))
        else:
            self.set_status(_("Search cleared. Showing all entries."))

    def collect_all_tags(self) -> list[str]:
        """
        Return a sorted list of unique tags present in the vault.
        """
        seen = set()
        entries = self.vault.iter_vault_entries()
        if isinstance(entries, dict):
            iterable = entries.values()
        else:
            iterable = entries

        for entry in iterable:
            tags = getattr(entry, "tags", None) or []
            for tag in tags:
                t = (tag or "").strip()
                if t:
                    seen.add(t)
        return sorted(seen)

    def open_password_generator(self, parent: tk.Toplevel, target_entry: tk.Entry):
        """
        Open a small window to generate a password.
        """
        gen = tk.Toplevel(parent)
        gen.title(_("Password generator"))
        gen.geometry("420x200")
        gen.resizable(False, False)
        gen.transient(parent)
        gen.grab_set()

        # Variables for UI settings.
        var_len = tk.IntVar(value=16)
        var_lower = tk.BooleanVar(value=True)
        var_upper = tk.BooleanVar(value=True)
        var_digits = tk.BooleanVar(value=True)
        var_symbols = tk.BooleanVar(value=True)
        var_avoid = tk.BooleanVar(value=True)
        var_out = tk.StringVar(value="")

        # UI.
        frm = ttk.Frame(gen, padding=10)
        frm.pack(fill="both", expand=True)

        # Length.
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=(0,6))
        ttk.Label(row, text=_("Length")).pack(side="left")
        sp = ttk.Spinbox(row, from_=8, to=64, textvariable=var_len, width=5)
        sp.pack(side="left", padx=(6,0))

        # Categories.
        cats = ttk.Frame(frm)
        cats.pack(fill="x")
        ttk.Checkbutton(cats, text=_("Lowercase (a_z)"), variable=var_lower).grid(row=0, column=0, sticky="w", padx=2)
        ttk.Checkbutton(cats, text=_("Uppercase (A-Z)"), variable=var_upper).grid(row=0, column=1, sticky="w", padx=12)
        ttk.Checkbutton(cats, text=_("Digits (0-9"), variable=var_digits).grid(row=1, column=0, sticky="w", padx=2, pady=(4,0))
        ttk.Checkbutton(cats, text=_("Symbols (!@#...)"), variable=var_symbols).grid(row=1, column=1, sticky="w", padx=12, pady=(4,0))
        ttk.Checkbutton(cats, text=_("Avoid common words and ambiguous characters (0/O, l/1/I"), variable=var_avoid)# .pack(anchor="w", pady=(6.4))

        # Output field for users.
        out_row = ttk.Frame(frm)
        out_row.pack(fill="x", pady=(6,6))
        ttk.Label(out_row, text=_("Generated password:")).pack(anchor="w")
        out_entry = ttk.Entry(out_row, textvariable=var_out, width=42)
        out_entry.pack(fill="x")

        # Actions.
        btn_row = ttk.Frame(frm)
        btn_row.pack(fill="x", pady=(8,0))

        def do_generate():
            try:
                pwd = secure_generate_password(
                    length=int(var_len.get()),
                    use_lower=bool(var_lower.get()),
                    use_upper=bool(var_upper.get()),
                    use_digits=bool(var_digits.get()),
                    use_symbols=bool(var_symbols.get()),
                    avoid_ambiguous=bool(var_avoid.get()),
                )
                var_out.set(pwd)
                # Select the text for a quick copy.
                out_entry.selection_range(0, tk.END)
            except Exception as exc:
                messagebox.showerror(_("Error"), str(exc))
                return

        def do_use_this():
            pwd = var_out.get()
            if not pwd:
                messagebox.showwarning(_("No password"), _("Please generate a password first."))
                return
            target_entry.delete(0, tk.END)
            target_entry.insert(0, pwd)
            gen.destroy()

        def do_copy():
            pwd = var_out.get()
            if not pwd:
               messagebox.showwarning(_("No password"), _("Please generate a password first."))
               return
            try:
                self.primary_main.clipboard_clear()
                self.primary_main.clipboard_append(pwd)
                self.set_status(_("Password copied to clipboard."))
                # Cleaning clipboard like other places.
                if hasattr(self, "schedule_clipboard_clear"):
                    self.schedule_clipboard_clear()
            except tk.TclError:
                messagebox.showerror(_("Error"), _("Couldn't copy the password to clipboard."))

        ttk.Button(btn_row, text=_("Generate"), command=do_generate).pack(side="left")
        ttk.Button(btn_row, text=_("Use this"), command=do_use_this).pack(side="left", padx=(6,0))
        ttk.Button(btn_row, text=_("Copy"), command=do_copy).pack(side="left", padx=(6,0))
        ttk.Button(btn_row, text=_("Close"), command=gen.destroy).pack(side="right")

        # 1rst generation is for convenience.
        do_generate()

        # Keyboard shortcuts, press ctrl+g to generate a password automatically.
        gen.bind("<Control-g>", lambda e:do_generate())

        # Centering.
        gen.update_idletasks()
        try:
            x = parent.winfo_rootx() + (parent.winfo_width() //2) - (gen.winfo_width() // 2)
            y = parent.winfo_rooty() + (parent.winfo_height() //2) - (gen.winfo_height() // 2)
            gen.geometry(f"+{x}+{y}")
        except Exception:
            pass

    def sort_by_column(self, col_id: str):
        """
        Sort the treeview row by column id.
        The id of the column is one of : Entry, Tags, Website or application path, Username and Password.
        """
        idx = self.col_index[col_id]
        reverse = self.sort_reverse.get(col_id, False)

        # Collect current rows.
        rows = []
        for item_id in self.tree.get_children():
            values = self.tree.item(item_id, "values")
            val = values[idx] if idx < len(values) else ""
            rows.append((val, item_id))

        # Case-insensitive sort.
        rows.sort(key=lambda item: (item[0] or "").lower(), reverse=reverse)

        # Reorder items.
        for newpos, (_value, _item_id) in enumerate(rows):
            self.tree.move(_item_id, "", newpos)

        # Toggle the direction of a new click.
        self.sort_reverse[col_id] = not reverse

        # Status feedback (optional).
        self.set_status(_("Sorted by '{}' ({}).").format(col_id, "desc" if reverse else "asc"))

    def setup_shortcuts(self):
        """
        For registering keyboard shortcuts.
        """
        self.primary_main.bind_all("<Control-n>",    lambda e: self.add_entry())
        self.primary_main.bind_all("<Control-e>",   lambda e: self.edit_entry())
        self.primary_main.bind_all("<F2>",          lambda e: self.edit_entry())
        self.primary_main.bind_all("<Delete>",      lambda e: self.delete_entry())

        # Password actions.
        self.primary_main.bind_all("<Control-c>",   lambda e: self.copy_password())
        self.primary_main.bind_all("<Control-s>",   lambda e: self.show_password())

        # Navigation / focus actions.
        self.primary_main.bind_all("<Control-f>",   lambda e: (self.search_var.set(""), self.search_entries.focus_set()))
        self.primary_main.bind_all("<Control-l>",   lambda e: self.tag_filter.focus_set())



# Characters that are often confused: O/0, l/I/1, etc.
AMBIGUOUS_CHARS = set("O0oIl1")

def secure_generate_password(
        length: int = 16,
        use_lower: bool = True,
        use_upper: bool = True,
        use_digits: bool = True,
        use_symbols : bool = True,
        avoid_ambiguous: bool = True
) -> str:
    """
    Generate a cryptographically secure password.
    Ensure at least one character from each selected category of characters.
    """
    if length < 8:
        raise ValueError(_("Length must be at least 8."))

    # Build the character's group.
    groups = []
    if use_lower:
        groups.append(list(string.ascii_lowercase))
    if use_upper:
        groups.append(list(string.ascii_uppercase))
    if use_digits:
        groups.append(list(string.digits))
    if use_symbols:
        # Conservative symbol set (can be modified).
        groups.append(list("!@#$^&*()-_=+[]{};:,.?/"))

    if not groups:
        raise ValueError(_("Select at least one character category."))

    # Option for removing ambiguous characters.
    if avoid_ambiguous:
        for g in groups:
            g[:] = [ch for ch in g if ch not in AMBIGUOUS_CHARS]

    # Combined pool.
    pool = [ch for g in groups for ch in g]
    if not pool:
        raise ValueError(_("No characters left after filtering the ambiguous group."))

    # Guarantee at least one from each group.from
    password_chars = [secrets.choice(g) for g in groups]

    # Fill the remaining length from the pool.
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(pool))

    # Shuffle for avoiding the predictable position of characters.
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)

