import os
import sys
import json
import customtkinter as ctk
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
from tkinter import messagebox, Toplevel, StringVar, filedialog
from docx import Document
from odf.opendocument import OpenDocumentText
from odf.text import P

# --- App Icon ---
APP_ICON_PATH = "Icons/Black_Hole_Icon.ico"  # <-- change to your .ico path

# --- Paths ---
local_appdata = os.getenv("LOCALAPPDATA")
nova_folder = os.path.join(local_appdata, "NovaFoundry")
os.makedirs(nova_folder, exist_ok=True)

db_path = os.path.join(nova_folder, "BlackHolePasswords.db")
settings_path = os.path.join(nova_folder, "settings.json")

# --- Helper: Derive Key from master password ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

# --- Initialize DB ---
def init_db():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            title TEXT,
            username TEXT,
            password TEXT,
            notes TEXT
        )
    ''')
    conn.commit()
    return conn, c

conn, c = init_db()

# --- Password Manager App ---
class PasswordManager(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Black Hole Password Manager")
        self.geometry("800x500")
        if os.path.exists(APP_ICON_PATH):
            self.iconbitmap(APP_ICON_PATH)

        self.master_password = None
        self.fernet = None
        self.salt = b"blackhole_salt"

        # Check settings
        self.settings = {"master_password_set": False}
        if os.path.exists(settings_path):
            try:
                with open(settings_path, "r") as f:
                    self.settings = json.load(f)
            except:
                self.settings = {"master_password_set": False}

        # Master password popup
        self.show_master_password_popup()

        # UI Setup
        self.cards_frame = ctk.CTkScrollableFrame(self, width=780, height=400)
        self.cards_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Buttons
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(pady=5)
        ctk.CTkButton(btn_frame, text="Create New", command=self.create_new_card).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Export DOCX", command=self.export_docx).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Export ODT", command=self.export_odt).pack(side="left", padx=5)

        # Load Cards
        self.load_cards()

    # --- Master Password Popup ---
    def show_master_password_popup(self):
        popup = ctk.CTkToplevel(self)
        popup.grab_set()
        popup.geometry("400x250")

        if not self.settings.get("master_password_set", False):
            popup.title("Set Master Password")
            ctk.CTkLabel(popup, text="Create Master Password", font=("Arial", 16)).pack(pady=10)

            pwd_var = StringVar()
            pwd_entry = ctk.CTkEntry(popup, placeholder_text="Master Password", show="*", textvariable=pwd_var)
            pwd_entry.pack(pady=5)

            def toggle_pwd():
                if pwd_entry.cget("show") == "*":
                    pwd_entry.configure(show="")
                else:
                    pwd_entry.configure(show="*")
            ctk.CTkButton(popup, text="Show/Hide", command=toggle_pwd).pack(pady=5)

            # Save path
            path_var = StringVar()
            def browse_path():
                file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
                if file_path:
                    path_var.set(file_path)
            ctk.CTkButton(popup, text="Select Save Path", command=browse_path).pack(pady=5)
            ctk.CTkLabel(popup, textvariable=path_var).pack(pady=5)

            def create_master():
                pwd = pwd_var.get()
                if not pwd:
                    messagebox.showerror("Error", "Master password required!")
                    return
                self.master_password = pwd
                self.fernet = Fernet(derive_key(pwd, self.salt))
                save_path = path_var.get()
                if save_path:
                    with open(save_path, "w") as f:
                        f.write(pwd)
                    messagebox.showinfo("Saved", f"Master password saved to {save_path}")
                # Save settings
                self.settings["master_password_set"] = True
                with open(settings_path, "w") as f:
                    json.dump(self.settings, f)
                popup.destroy()

            ctk.CTkButton(popup, text="Create", command=create_master).pack(pady=10)
        else:
            popup.title("Enter Master Password")
            ctk.CTkLabel(popup, text="Enter Master Password", font=("Arial", 16)).pack(pady=20)

            pwd_var = StringVar()
            pwd_entry = ctk.CTkEntry(popup, placeholder_text="Master Password", show="*", textvariable=pwd_var)
            pwd_entry.pack(pady=5)

            def toggle_pwd():
                if pwd_entry.cget("show") == "*":
                    pwd_entry.configure(show="")
                else:
                    pwd_entry.configure(show="*")
            ctk.CTkButton(popup, text="Show/Hide", command=toggle_pwd).pack(pady=5)

            def unlock_master():
                pwd = pwd_var.get()
                if not pwd:
                    messagebox.showerror("Error", "Master password required!")
                    return
                try:
                    fernet_test = Fernet(derive_key(pwd, self.salt))
                    row = c.execute("SELECT password FROM passwords WHERE password IS NOT NULL LIMIT 1").fetchone()
                    if row and row[0]:
                        fernet_test.decrypt(row[0].encode())  # will raise if wrong
                    self.master_password = pwd
                    self.fernet = fernet_test
                    popup.destroy()
                except:
                    messagebox.showerror("Error", "Incorrect master password!")

            ctk.CTkButton(popup, text="Unlock", command=unlock_master).pack(pady=10)

        self.wait_window(popup)  # Wait until popup closes

    # --- Load Cards ---
    def load_cards(self):
        for widget in self.cards_frame.winfo_children():
            widget.destroy()
        for row in c.execute("SELECT id, title, username, password, notes FROM passwords"):
            id_, title, user, pwd_enc, notes = row
            pwd = self.fernet.decrypt(pwd_enc.encode()).decode() if pwd_enc else ""
            card = ctk.CTkFrame(self.cards_frame, corner_radius=10, fg_color="#0b0b0f")
            card.pack(pady=8, padx=10, fill="x")

            # Hover glow
            def on_hover(e, frame=card):
                frame.configure(fg_color="#1a1a2e")
            def off_hover(e, frame=card):
                frame.configure(fg_color="#0b0b0f")
            card.bind("<Enter>", on_hover)
            card.bind("<Leave>", off_hover)

            # Hidden password
            pwd_var = StringVar(value="*"*len(pwd) if pwd else "")
            def toggle_password():
                if pwd_var.get().startswith("*"):
                    pwd_var.set(pwd)
                else:
                    pwd_var.set("*"*len(pwd))

            label_text = f"Title: {title}\nUsername: {user or ''}\nPassword: "
            label = ctk.CTkLabel(card, textvariable=pwd_var, justify="left")
            label.pack(side="left", padx=10, pady=10)
            lbl_title = ctk.CTkLabel(card, text=label_text, justify="left")
            lbl_title.pack(side="left", padx=(10,0), pady=10)

            # Buttons
            btns = ctk.CTkFrame(card)
            btns.pack(side="right", padx=10)
            ctk.CTkButton(btns, text="Show", command=toggle_password, width=60).pack(pady=2)
            ctk.CTkButton(btns, text="Edit", command=lambda id=id_: self.edit_card_popup(id)).pack(pady=2)
            ctk.CTkButton(btns, text="Delete", command=lambda id=id_: self.delete_card(id)).pack(pady=2)

    # --- Create Card ---
    def create_new_card(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Create New Password")
        popup.geometry("400x200")
        popup.grab_set()

        ctk.CTkLabel(popup, text="Title:", font=("Arial", 14)).pack(pady=10)
        title_var = StringVar()
        ctk.CTkEntry(popup, textvariable=title_var).pack(pady=5)

        def create_card():
            title = title_var.get()
            if not title:
                messagebox.showerror("Error", "Title required!")
                return
            c.execute("INSERT INTO passwords (title, username, password, notes) VALUES (?, ?, ?, ?)",
                      (title, "", "", ""))
            conn.commit()
            self.load_cards()
            popup.destroy()

        ctk.CTkButton(popup, text="Create", command=create_card).pack(pady=20)

    # --- Edit Card Popup ---
    def edit_card_popup(self, id_):
        row = c.execute("SELECT title, username, password, notes FROM passwords WHERE id=?", (id_,)).fetchone()
        title, user, pwd_enc, notes = row
        pwd = self.fernet.decrypt(pwd_enc.encode()).decode() if pwd_enc else ""
        popup = ctk.CTkToplevel(self)
        popup.title("Edit Password")
        popup.geometry("400x400")
        popup.grab_set()

        ctk.CTkLabel(popup, text="Title:", font=("Arial", 12)).pack(pady=5)
        title_var = StringVar(value=title)
        ctk.CTkEntry(popup, textvariable=title_var).pack(pady=5)

        ctk.CTkLabel(popup, text="Username:", font=("Arial", 12)).pack(pady=5)
        user_var = StringVar(value=user)
        ctk.CTkEntry(popup, textvariable=user_var).pack(pady=5)

        ctk.CTkLabel(popup, text="Password:", font=("Arial", 12)).pack(pady=5)
        pwd_var = StringVar(value=pwd)
        pwd_entry = ctk.CTkEntry(popup, textvariable=pwd_var, show="*")
        pwd_entry.pack(pady=5)

        def toggle_pwd():
            if pwd_entry.cget('show') == "*":
                pwd_entry.config(show="")
            else:
                pwd_entry.config(show="*")
        ctk.CTkButton(popup, text="Show/Hide", command=toggle_pwd).pack(pady=5)

        ctk.CTkLabel(popup, text="Notes:", font=("Arial", 12)).pack(pady=5)
        notes_var = StringVar(value=notes)
        ctk.CTkEntry(popup, textvariable=notes_var).pack(pady=5)

        def save_card():
            encrypted_pwd = self.fernet.encrypt(pwd_var.get().encode()).decode() if pwd_var.get() else ""
            c.execute("UPDATE passwords SET title=?, username=?, password=?, notes=? WHERE id=?",
                      (title_var.get(), user_var.get(), encrypted_pwd, notes_var.get(), id_))
            conn.commit()
            self.load_cards()
            popup.destroy()

        ctk.CTkButton(popup, text="Save", command=save_card).pack(pady=20)

    # --- Delete ---
    def delete_card(self, id_):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
            c.execute("DELETE FROM passwords WHERE id=?", (id_,))
            conn.commit()
            self.load_cards()

    # --- Export ---
    def export_docx(self):
        doc = Document()
        for row in c.execute("SELECT title, username, password, notes FROM passwords"):
            title, user, pwd_enc, notes = row
            pwd = self.fernet.decrypt(pwd_enc.encode()).decode() if pwd_enc else ""
            doc.add_paragraph(f"Title: {title}\nUsername: {user or ''}\nPassword: {pwd}\nNotes: {notes or ''}\n\n")
        doc.save("passwords.docx")
        messagebox.showinfo("Exported", "Passwords exported as passwords.docx")

    def export_odt(self):
        odt = OpenDocumentText()
        for row in c.execute("SELECT title, username, password, notes FROM passwords"):
            title, user, pwd_enc, notes = row
            pwd = self.fernet.decrypt(pwd_enc.encode()).decode() if pwd_enc else ""
            odt.text.addElement(P(text=f"Title: {title}\nUsername: {user or ''}\nPassword: {pwd}\nNotes: {notes or ''}\n"))
        odt.save("passwords.odt")
        messagebox.showinfo("Exported", "Passwords exported as passwords.odt")


# --- Run App ---
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    app = PasswordManager()
    app.mainloop()