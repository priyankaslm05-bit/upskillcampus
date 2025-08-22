import tkinter as tk
from tkinter import messagebox
import sqlite3
import bcrypt
import secrets
import string
from cryptography.fernet import Fernet
import os

# Generate encryption key if not exists
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())

with open("secret.key", "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

# Database setup
conn = sqlite3.connect("database.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS passwords(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    account TEXT,
    username TEXT,
    password TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")
conn.commit()

# Application class
class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")
        self.master.geometry("400x300")
        self.user_id = None
        self.login_screen()

    def clear_screen(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    def login_screen(self):
        self.clear_screen()
        tk.Label(self.master, text="Login", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.master, text="Username").pack()
        username_entry = tk.Entry(self.master)
        username_entry.pack()

        tk.Label(self.master, text="Password").pack()
        password_entry = tk.Entry(self.master, show="*")
        password_entry.pack()

        def login():
            username = username_entry.get()
            password = password_entry.get()
            cursor.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
            result = cursor.fetchone()
            if result and bcrypt.checkpw(password.encode(), result[1]):
                self.user_id = result[0]
                self.dashboard()
            else:
                messagebox.showerror("Error", "Invalid credentials")

        def register():
            self.register_screen()

        tk.Button(self.master, text="Login", command=login).pack(pady=5)
        tk.Button(self.master, text="Register", command=register).pack()

    def register_screen(self):
        self.clear_screen()
        tk.Label(self.master, text="Register", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.master, text="Username").pack()
        username_entry = tk.Entry(self.master)
        username_entry.pack()

        tk.Label(self.master, text="Password").pack()
        password_entry = tk.Entry(self.master, show="*")
        password_entry.pack()

        def register_user():
            username = username_entry.get()
            password = password_entry.get()
            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            try:
                cursor.execute("INSERT INTO users(username, password_hash) VALUES (?,?)", (username, hashed_pw))
                conn.commit()
                messagebox.showinfo("Success", "User registered successfully")
                self.login_screen()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists")

        tk.Button(self.master, text="Register", command=register_user).pack(pady=5)
        tk.Button(self.master, text="Back to Login", command=self.login_screen).pack()

    def dashboard(self):
        self.clear_screen()
        tk.Label(self.master, text="Password Manager Dashboard", font=("Arial", 14)).pack(pady=10)

        tk.Button(self.master, text="Add Password", command=self.add_password_screen).pack(pady=5)
        tk.Button(self.master, text="View Passwords", command=self.view_passwords).pack(pady=5)
        tk.Button(self.master, text="Logout", command=self.login_screen).pack(pady=5)

    def add_password_screen(self):
        self.clear_screen()
        tk.Label(self.master, text="Add Password", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.master, text="Account").pack()
        account_entry = tk.Entry(self.master)
        account_entry.pack()

        tk.Label(self.master, text="Username").pack()
        username_entry = tk.Entry(self.master)
        username_entry.pack()

        tk.Label(self.master, text="Password").pack()
        password_entry = tk.Entry(self.master)
        password_entry.pack()

        def generate_password():
            chars = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(secrets.choice(chars) for _ in range(12))
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)

        def save_password():
            account = account_entry.get()
            uname = username_entry.get()
            pwd = fernet.encrypt(password_entry.get().encode())
            cursor.execute("INSERT INTO passwords(user_id, account, username, password) VALUES (?,?,?,?)",
                           (self.user_id, account, uname, pwd))
            conn.commit()
            messagebox.showinfo("Success", "Password saved successfully")
            self.dashboard()

        tk.Button(self.master, text="Generate Password", command=generate_password).pack(pady=5)
        tk.Button(self.master, text="Save", command=save_password).pack(pady=5)
        tk.Button(self.master, text="Back", command=self.dashboard).pack()

    def view_passwords(self):
        self.clear_screen()
        tk.Label(self.master, text="Stored Passwords", font=("Arial", 16)).pack(pady=10)
        cursor.execute("SELECT account, username, password FROM passwords WHERE user_id=?", (self.user_id,))
        rows = cursor.fetchall()
        for account, uname, pwd in rows:
            decrypted_pwd = fernet.decrypt(pwd).decode()
            tk.Label(self.master, text=f"{account} | {uname} | {decrypted_pwd}").pack()
        tk.Button(self.master, text="Back", command=self.dashboard).pack(pady=5)

root = tk.Tk()
app = PasswordManager(root)
root.mainloop()
