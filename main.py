import customtkinter as ctk
import sqlite3
from cryptography.fernet import Fernet
from tkinter import simpledialog, messagebox
from docx import Document
from odf.opendocument import OpenDocumentText
from odf.text import P

# --- Encryption Setup ---
# In real app, derive key from master password
key = Fernet.generate_key()
cipher = Fernet(key)

# --- Database Setup ---
conn = sqlite3.connect("passwords.db")
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

# --- Password Manager App ---
class PasswordManager(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Black Hole Password Manager")
        self.geometry("700x500")
        self.cards_frame = ctk.CTkScrollableFrame(self, width=680, height=400)
        self.cards_frame.pack(pady=10, padx=10, fill="both", expand=True)
        self.load_cards()

        # Buttons
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(pady=5)
        ctk.CTkButton(btn_frame, text="Add Password", command=self.add_card_dialog).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Export DOCX", command=self.export_docx).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Export ODT", command=self.export_odt).pack(side="left", padx=5)

    # --- Load Cards ---
    def load_cards(self):
        for widget in self.cards_frame.winfo_children():
            widget.destroy()
        for row in c.execute("SELECT id, title, username, password, notes FROM passwords"):
            id_, title, user, pwd, notes = row
            pwd = cipher.decrypt(pwd.encode()).decode()
            card = ctk.CTkFrame(self.cards_frame, corner_radius=10, fg_color="#2c2f33")
            card.pack(pady=8, padx=10, fill="x")

            def on_hover(e, frame=card):
                frame.configure(fg_color="#3b3f44")
            def off_hover(e, frame=card):
                frame.configure(fg_color="#2c2f33")

            card.bind("<Enter>", on_hover)
            card.bind("<Leave>", off_hover)

            text = f"Title: {title}\nUsername: {user}\nPassword: {pwd}\nNotes: {notes}"
            label = ctk.CTkLabel(card, text=text, justify="left")
            label.pack(side="left", padx=10, pady=10)

            # Edit / Delete buttons
            btns = ctk.CTkFrame(card)
            btns.pack(side="right", padx=10)
            ctk.CTkButton(btns, text="Edit", command=lambda id=id_: self.edit_card_dialog(id)).pack(pady=2)
            ctk.CTkButton(btns, text="Delete", command=lambda id=id_: self.delete_card(id)).pack(pady=2)

    # --- Add / Edit / Delete ---
    def add_card_dialog(self):
        title = simpledialog.askstring("Title", "Service/Title:")
        if not title: return
        user = simpledialog.askstring("Username", "Username:")
        pwd = simpledialog.askstring("Password", "Password:")
        notes = simpledialog.askstring("Notes", "Other Info:")
        self.add_card(title, user, pwd, notes)

    def add_card(self, title, user, pwd, notes):
        encrypted_pwd = cipher.encrypt(pwd.encode()).decode()
        c.execute("INSERT INTO passwords (title, username, password, notes) VALUES (?, ?, ?, ?)",
                  (title, user, encrypted_pwd, notes))
        conn.commit()
        self.load_cards()

    def edit_card_dialog(self, id_):
        row = c.execute("SELECT title, username, password, notes FROM passwords WHERE id=?", (id_,)).fetchone()
        title, user, pwd_enc, notes = row
        pwd = cipher.decrypt(pwd_enc.encode()).decode()
        title_new = simpledialog.askstring("Title", "Service/Title:", initialvalue=title)
        if not title_new: return
        user_new = simpledialog.askstring("Username", "Username:", initialvalue=user)
        pwd_new = simpledialog.askstring("Password", "Password:", initialvalue=pwd)
        notes_new = simpledialog.askstring("Notes", "Other Info:", initialvalue=notes)
        encrypted_pwd = cipher.encrypt(pwd_new.encode()).decode()
        c.execute("UPDATE passwords SET title=?, username=?, password=?, notes=? WHERE id=?",
                  (title_new, user_new, encrypted_pwd, notes_new, id_))
        conn.commit()
        self.load_cards()

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
            pwd = cipher.decrypt(pwd_enc.encode()).decode()
            doc.add_paragraph(f"Title: {title}\nUsername: {user}\nPassword: {pwd}\nNotes: {notes}\n\n")
        doc.save("passwords.docx")
        messagebox.showinfo("Exported", "Passwords exported as passwords.docx")

    def export_odt(self):
        odt = OpenDocumentText()
        for row in c.execute("SELECT title, username, password, notes FROM passwords"):
            title, user, pwd_enc, notes = row
            pwd = cipher.decrypt(pwd_enc.encode()).decode()
            odt.text.addElement(P(text=f"Title: {title}\nUsername: {user}\nPassword: {pwd}\nNotes: {notes}\n"))
        odt.save("passwords.odt")
        messagebox.showinfo("Exported", "Passwords exported as passwords.odt")


# --- Run App ---
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = PasswordManager()
    app.mainloop()