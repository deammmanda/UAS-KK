from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

# Membuat pasangan kunci RSA
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Membuat enkripsi file menggunakan AES
def encrypt_file(file_path, output_path, aes_key, save_as_text=False):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        data = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(data)

    if save_as_text:
        # Simpan dalam format Base64
        base64_data = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
        with open(output_path, 'w') as f:
            f.write(base64_data)
    else:
        # Simpan dalam format biner
        with open(output_path, 'wb') as f:
            f.write(cipher.nonce + tag + ciphertext)

    # Simpan ekstensi file asli
    original_extension = os.path.splitext(file_path)[1]
    with open("file_metadata.txt", "w") as meta_file:
        meta_file.write(original_extension)

# Dekripsi file menggunakan AES
def decrypt_file(file_path, output_path, aes_key, is_text=False):
    if is_text:
        with open(file_path, 'r') as f:
            encrypted_data = base64.b64decode(f.read())
    else:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_path, 'wb') as f:
        f.write(data)

# Enkripsi kunci AES menggunakan RSA
def encrypt_aes_key(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(aes_key)

# Dekripsi kunci AES menggunakan RSA
def decrypt_aes_key(encrypted_aes_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(encrypted_aes_key)

# Program utama
def main():
    def generate_keys():
        private_key, public_key = generate_rsa_keys()
        with open("private.pem", "wb") as f:
            f.write(private_key)
        with open("public.pem", "wb") as f:
            f.write(public_key)
        messagebox.showinfo("Success", "RSA keys generated and saved!")

    def encrypt_action():
        file_path = filedialog.askopenfilename(
            title="Select File to Encrypt",
            filetypes=[("All Files", "*.*"), ("PDF Files", "*.pdf"), ("Word Documents", "*.docx"),
                       ("Text Files", "*.txt"), ("PowerPoint Presentations", "*.pptx")]
        )
        if not file_path:
            return

        output_path = filedialog.asksaveasfilename(
            title="Save Encrypted File",
            defaultextension=".enc",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if not output_path:
            return

        save_as_text = messagebox.askyesno("Format", "Save as Base64 format?")

        # Generate AES key and encrypt it
        aes_key = get_random_bytes(16)  # 128-bit key
        with open("public.pem", "rb") as f:
            public_key = f.read()
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

        # Save encrypted AES key
        with open("aes_key.enc", "wb") as f:
            f.write(encrypted_aes_key)

        # Encrypt the file
        encrypt_file(file_path, output_path, aes_key, save_as_text)
        messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_action():
        file_path = filedialog.askopenfilename(
            title="Select File to Decrypt",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        # Baca ekstensi file asli dari metadata
        if not os.path.exists("file_metadata.txt"):
            messagebox.showerror("Error", "Metadata file not found!")
            return
        with open("file_metadata.txt", "r") as meta_file:
            original_extension = meta_file.read().strip()

        # Tentukan path untuk menyimpan file hasil dekripsi
        output_path = filedialog.asksaveasfilename(
            title="Save Decrypted File",
            defaultextension=original_extension,
            filetypes=[("All Files", "*.*")]
        )
        if not output_path:
            return

        is_text = messagebox.askyesno("Format", "Is the encrypted file in Base64 format?")

        # Load encrypted AES key
        with open("aes_key.enc", "rb") as f:
            encrypted_aes_key = f.read()

        # Decrypt AES key
        with open("private.pem", "rb") as f:
            private_key = f.read()
        aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

        # Decrypt the file
        decrypt_file(file_path, output_path, aes_key, is_text)
        messagebox.showinfo("Success", "File decrypted successfully!")

    # Setup GUI
    root = tk.Tk()
    root.title("Hybrid Encryption Program")

    tk.Button(root, text="Generate RSA Keys", command=generate_keys, width=30, bg="pink", fg="black").pack(pady=10)
    tk.Button(root, text="Encrypt File", command=encrypt_action, width=30, bg="lightblue", fg="black").pack(pady=10)
    tk.Button(root, text="Decrypt File", command=decrypt_action, width=30, bg="lightgreen", fg="black").pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
