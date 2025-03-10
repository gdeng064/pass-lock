import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import sqlite3
from cryptography.fernet import Fernet
import os
import pyperclip
import pyotp
import qrcode

# Declare global variables
conn = None
cursor = None
cipher_suite = None
secret_key = None  # Store the TOTP secret key here
MASTER_PASSWORD_FILE = "master_password.dat"
TOTP_SECRET_FILE = "totp_secret.dat"

def encrypt_data(data):
    """Encrypts data using the cipher suite."""
    return cipher_suite.encrypt(data.encode())

def decrypt_data(data):
    """Decrypts data using the cipher_suite."""
    return cipher_suite.decrypt(data).decode()

def check_master_password():
    """Prompt the user for the master password and check if it matches the stored one."""
    master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')

    if not os.path.exists(MASTER_PASSWORD_FILE):
        messagebox.showerror("Error", "Master password file not found.")
        return False

    with open(MASTER_PASSWORD_FILE, 'rb') as f:
        encrypted_master_password = f.read()
        stored_master_password = decrypt_data(encrypted_master_password)

    if master_password == stored_master_password:
        return True
    else:
        messagebox.showerror("Access Denied", "Incorrect master password.")
        return False

def create_master_password():
    """Prompt the user to create a new master password and store it securely."""
    master_password = simpledialog.askstring("Create Master Password", "Create a new master password:", show='*')
    confirm_password = simpledialog.askstring("Confirm Master Password", "Confirm your master password:", show='*')

    if master_password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match. Please try again.")
        return False

    encrypted_password = encrypt_data(master_password)
    with open(MASTER_PASSWORD_FILE, 'wb') as f:
        f.write(encrypted_password)

    messagebox.showinfo("Success", "Master password created successfully!")
    return True

def initialize_master_password():
    """Check if a master password exists; if not, prompt the user to create one."""
    if not os.path.exists(MASTER_PASSWORD_FILE):
        return create_master_password()
    return True

def initialize_totp():
    """Initialize TOTP if it's not already set up."""
    global secret_key

    if not os.path.exists(TOTP_SECRET_FILE):
        # Create a new secret key
        secret_key = pyotp.random_base32()
        
        # Generate a QR code for the secret key
        totp_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name="PassLock", issuer_name="PassLock")
        qr = qrcode.make(totp_uri)
        qr.show()  # Display the QR code for scanning with Google Authenticator

        # Save the TOTP secret to a file
        with open(TOTP_SECRET_FILE, 'w') as f:
            f.write(secret_key)
        
        messagebox.showinfo("TOTP Setup", "Scan the QR code with Google Authenticator to set up MFA.")
    else:
        # Load the TOTP secret if already set up
        with open(TOTP_SECRET_FILE, 'r') as f:
            secret_key = f.read()

def verify_totp():
    """Verify TOTP code."""
    totp_code = simpledialog.askstring("TOTP", "Enter the 6-digit code from Google Authenticator:")
    
    if totp_code:
        totp = pyotp.TOTP(secret_key)  # Use the loaded or generated secret key
        if totp.verify(totp_code):
            messagebox.showinfo("Success", "TOTP code is correct.")
            return True  # Proceed to open the main password manager
        else:
            messagebox.showerror("Error", "TOTP code is incorrect.")
            return False
    else:
        messagebox.showwarning("Input Error", "Please enter a valid TOTP code.")
        return False

def add_password():
    """Function to add a new password entry."""
    website = simpledialog.askstring("Website", "Enter website:")
    username = simpledialog.askstring("Username", "Enter username:")
    password = simpledialog.askstring("Password", "Enter password:", show='*')
    url = simpledialog.askstring("URL", "Enter URL (optional):")

    if website and username and password:
        encrypted_password = encrypt_data(password)
        cursor.execute("INSERT INTO passwords (website, username, password, url) VALUES (?, ?, ?, ?)",
                       (website, username, encrypted_password, url))
        conn.commit()
        messagebox.showinfo("Success", "Password added successfully!")
        update_password_list()  # Refresh the password list
    else:
        messagebox.showwarning("Input Error", "Please fill all fields.")

def update_password_list():
    """Update the displayed password list in the Treeview."""
    for row in tree.get_children():
        tree.delete(row)

    cursor.execute("SELECT website, username, password, url FROM passwords")
    rows = cursor.fetchall()
    
    for row in rows:
        # Retrieve and print the encrypted password for debugging
        encrypted_password = row[2]  # This is the actual encrypted password
        masked_password = '*' * 8  # Mask the password for display
        tree.insert("", tk.END, values=(row[0], row[1], masked_password, row[3] or ''))

def copy_to_clipboard(text, is_password=False):
    """Copy text to clipboard and show either 'Password copied' or 'Username copied'."""
    pyperclip.copy(text)
    if is_password:
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showinfo("Copied", "Username copied to clipboard!")

def get_real_password(website):
    """Retrieve the real encrypted password for the given website."""
    cursor.execute("SELECT password FROM passwords WHERE website=?", (website,))
    result = cursor.fetchone()
    if result:
        encrypted_password = result[0]
        return encrypted_password
    else:
        return None  # Handle the case where no password is found

def copy_password():
    """Copy the selected password to the clipboard."""
    selected_entry = get_selected_entry()
    if selected_entry:
        encrypted_password = get_real_password(selected_entry[0])
        if encrypted_password:
            decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
            copy_to_clipboard(decrypted_password, is_password=True)  # This ensures 'Password copied'
        else:
            messagebox.showwarning("Error", "Password not found.")

def get_selected_entry():
    """Get the currently selected entry from the Treeview."""
    selected_item = tree.selection()
    if selected_item:
        entry_values = tree.item(selected_item)['values']
        return entry_values
    messagebox.showwarning("Warning", "No entry selected. Please select an entry first.")
    return None


def delete_password():
    """Delete the selected password entry."""
    selected = get_selected_entry()
    if selected:
        cursor.execute("DELETE FROM passwords WHERE website = ? AND username = ?", (selected[0], selected[1]))
        conn.commit()
        update_password_list()
        messagebox.showinfo("Deleted", "Password entry deleted.")

def edit_password():
    """Edit the selected password entry."""
    selected = get_selected_entry()
    if selected:
        new_password = simpledialog.askstring("Edit Password", "Enter new password:", show='*')
        if new_password:
            encrypted_password = encrypt_data(new_password)
            cursor.execute("UPDATE passwords SET password = ? WHERE website = ? AND username = ?", 
                           (encrypted_password, selected[0], selected[1]))
            conn.commit()
            update_password_list()
            messagebox.showinfo("Updated", "Password updated successfully.")

def on_right_click(event):
    """Show context menu on right-click."""
    context_menu.post(event.x_root, event.y_root)

def main():
    global conn, cursor, cipher_suite, tree, context_menu

    # Retrieve encryption key from environment variable
    key = os.environ.get('FERNET_KEY')
    if not key:
        messagebox.showerror("Error", "FERNET_KEY environment variable is not set.")
        return
    
    cipher_suite = Fernet(key)

    # Initialize master password, allow creation if it doesn't exist
    if not initialize_master_password():
        return  # Exit if the master password setup failed

    # Check master password before accessing the app
    if not check_master_password():
        return  # If the master password is incorrect, terminate the app

    # Initialize TOTP (if it doesn't exist, prompt the user to set it up)
    initialize_totp()

    # Verify TOTP
    if not verify_totp():
        return  # If TOTP verification fails, terminate the app

    # Create SQLite database to store passwords
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                    (id INTEGER PRIMARY KEY, website TEXT, username TEXT, password TEXT, url TEXT)''')
    conn.commit()

    # GUI setup
    root = tk.Tk()
    root.title("PassLock")

    # Create Treeview for displaying passwords
    tree = ttk.Treeview(root, columns=("Website", "Username", "Password", "URL"), show="headings")
    tree.heading("Website", text="Website")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")
    tree.heading("URL", text="URL")
    tree.column("Website", anchor=tk.W)
    tree.column("Username", anchor=tk.W)
    tree.column("Password", anchor=tk.W)
    tree.column("URL", anchor=tk.W)
    tree.pack(fill=tk.BOTH, expand=True)

    # Add buttons for operations
    btn_frame = tk.Frame(root)
    btn_frame.pack(fill=tk.X)

    add_button = tk.Button(btn_frame, text="Add Password", command=add_password)
    add_button.pack(side=tk.LEFT, padx=5, pady=5)

    copy_button = tk.Button(btn_frame, text="Copy Password", command=copy_password)
    copy_button.pack(side=tk.LEFT, padx=5, pady=5)

    delete_button = tk.Button(btn_frame, text="Delete Password", command=delete_password)
    delete_button.pack(side=tk.LEFT, padx=5, pady=5)

    edit_button = tk.Button(btn_frame, text="Edit Password", command=edit_password)
    edit_button.pack(side=tk.LEFT, padx=5, pady=5)

    # Bind right-click to show context menu
    context_menu = tk.Menu(root, tearoff=0)
    context_menu.add_command(label="Copy Username", command=lambda: copy_to_clipboard(get_selected_entry()[1]))
    context_menu.add_command(label="Copy Password", command=copy_password)
    context_menu.add_command(label="Edit Password", command=edit_password)
    context_menu.add_command(label="Delete Password", command=delete_password)
    tree.bind("<Button-3>", on_right_click)

    # Load existing passwords into the Treeview
    update_password_list()

    root.mainloop()

    # Clean up the database connection
    if conn:
        conn.close()

if __name__ == "__main__":
    main()
