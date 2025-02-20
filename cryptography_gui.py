import tkinter as tk
from tkinter import messagebox
from aes_encrypt_decrypt import AES
from des_encrypt_decrypt import DES, ECB, CBC  
from des3_encrypt_decrypt import TripleDES

# Initialize algorithms
aes = AES()
des = DES(key=b"12345678", mode=ECB)  #
des3 = TripleDES(key=b"1234567812345678", mode=ECB)

# Function to handle encryption/decryption
def encrypt_decrypt():
    alg = algo_var.get()
    key = key_entry.get().encode()
    text = text_entry.get().encode()
    action = action_var.get()

    try:
        if alg == 'AES':
            if len(key) != 32:
                raise ValueError("AES Key must be 32 characters (128-bit).")
            if len(text) != 32:
                raise ValueError("AES Text must be 32 characters.")
            result = aes.encrypt(text.decode(), key.decode()) if action == "Encrypt" else aes.decrypt(text.decode(), key.decode())

        elif alg == 'DES':
            if len(key) != 8:
                raise ValueError("DES Key must be 8 bytes long.")
            result = des.encrypt(text) if action == "Encrypt" else des.decrypt(text)

        elif alg == '3DES':
            if len(key) not in [16, 24]:
                raise ValueError("3DES Key must be 16 or 24 bytes long.")
            result = des3.encrypt(text) if action == "Encrypt" else des3.decrypt(text)

        result_entry.delete(0, tk.END)
        result_entry.insert(0, result.hex())

    except Exception as e:
        messagebox.showerror("Error", str(e))

# Setting up the GUI
root = tk.Tk()
root.title("Cryptography Tool")
root.geometry("450x300")

# Algorithm selection
tk.Label(root, text="Algorithm:").grid(row=0, column=0, padx=10, pady=5)
algo_var = tk.StringVar(root)
algo_var.set("AES")
tk.OptionMenu(root, algo_var, "AES", "DES", "3DES").grid(row=0, column=1, padx=10, pady=5)

# Key input
tk.Label(root, text="Key:").grid(row=1, column=0, padx=10, pady=5)
key_entry = tk.Entry(root, width=30)
key_entry.grid(row=1, column=1, padx=10, pady=5)

# Text input
tk.Label(root, text="Text:").grid(row=2, column=0, padx=10, pady=5)
text_entry = tk.Entry(root, width=30)
text_entry.grid(row=2, column=1, padx=10, pady=5)

# Action selection (Encrypt/Decrypt)
action_var = tk.StringVar(root)
action_var.set("Encrypt")
tk.OptionMenu(root, action_var, "Encrypt", "Decrypt").grid(row=3, column=0, padx=10, pady=5)
tk.Button(root, text="Go", command=encrypt_decrypt).grid(row=3, column=1, padx=10, pady=5)

# Result field
tk.Label(root, text="Result:").grid(row=4, column=0, padx=10, pady=5)
result_entry = tk.Entry(root, width=40)
result_entry.grid(row=4, column=1, padx=10, pady=5)

root.mainloop()
