from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import time
import psutil
import datetime

class PerformanceTracker:
    def __init__(self, tree):
        self.records = []
        self.tree = tree
        
    def track_operation(self, operation_type, file_size, start_time, end_time):
        process = psutil.Process(os.getpid())
        record = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'operation': operation_type,
            'file_size_mb': round(file_size / (1024 * 1024), 2),
            'duration_seconds': round(end_time - start_time, 2),
            'memory_usage_mb': round(process.memory_info().rss / (1024 * 1024), 2),
            'cpu_percent': round(process.cpu_percent(), 2)
        }
        self.records.append(record)
        self.update_tree(record)
        return record
    
    def update_tree(self, record):
        # Menambahkan record baru ke treeview
        self.tree.insert('', 'end', values=(
            record['timestamp'],
            record['operation'],
            record['file_size_mb'],
            record['duration_seconds'],
            record['memory_usage_mb'],
            record['cpu_percent']
        ))

def generate_rsa_keys(tracker):
    start_time = time.time()
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    end_time = time.time()
    
    if tracker:
        tracker.track_operation('Generate RSA Keys', 0, start_time, end_time)
    
    return private_key, public_key

def encrypt_aes_key(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(aes_key)

def decrypt_aes_key(encrypted_aes_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(encrypted_aes_key)

def encrypt_file(file_path, output_path, aes_key, save_as_text=False, tracker=None):
    start_time = time.time()
    file_size = os.path.getsize(file_path)
    
    cipher = AES.new(aes_key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        data = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(data)

    if save_as_text:
        base64_data = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
        with open(output_path, 'w') as f:
            f.write(base64_data)
    else:
        with open(output_path, 'wb') as f:
            f.write(cipher.nonce + tag + ciphertext)

    original_extension = os.path.splitext(file_path)[1]
    with open("file_metadata.txt", "w") as meta_file:
        meta_file.write(original_extension)
    
    end_time = time.time()
    if tracker:
        tracker.track_operation('Encryption', file_size, start_time, end_time)

def decrypt_file(file_path, output_path, aes_key, is_text=False, tracker=None):
    start_time = time.time()
    file_size = os.path.getsize(file_path)
    
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
    
    end_time = time.time()
    if tracker:
        tracker.track_operation('Decryption', file_size, start_time, end_time)

def main():
    root = tk.Tk()
    root.title("Hybrid Encryption Program")
    
    # Mengatur ukuran minimum window
    root.geometry("800x600")
    root.minsize(800, 600)
    
    # Frame untuk tombol-tombol
    button_frame = tk.Frame(root, padx=20, pady=20)
    button_frame.pack(fill='x')
    
    # Frame untuk judul tabel
    title_frame = tk.Frame(root, padx=20)
    title_frame.pack(fill='x')
    
    # Frame untuk tabel
    table_frame = tk.Frame(root, padx=20)
    table_frame.pack(fill='both', expand=True)
    
    # Membuat dan mengatur Treeview
    tree = ttk.Treeview(table_frame)
    tree['columns'] = ('Timestamp', 'Operation', 'File Size (MB)', 'Duration (s)', 'Memory (MB)', 'CPU (%)')
    
    # Format kolom
    tree.column('#0', width=0, stretch=tk.NO)
    tree.column('Timestamp', width=150)
    tree.column('Operation', width=100)
    tree.column('File Size (MB)', width=100)
    tree.column('Duration (s)', width=100)
    tree.column('Memory (MB)', width=100)
    tree.column('CPU (%)', width=100)
    
    # Heading kolom
    tree.heading('#0', text='')
    tree.heading('Timestamp', text='Timestamp')
    tree.heading('Operation', text='Operation')
    tree.heading('File Size (MB)', text='File Size (MB)')
    tree.heading('Duration (s)', text='Duration (s)')
    tree.heading('Memory (MB)', text='Memory (MB)')
    tree.heading('CPU (%)', text='CPU (%)')
    
    # Menambahkan scrollbar
    scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    
    performance_tracker = PerformanceTracker(tree)
    
    def generate_keys_action():
        try:
            private_key, public_key = generate_rsa_keys(performance_tracker)
            with open("private.pem", "wb") as f:
                f.write(private_key)
            with open("public.pem", "wb") as f:
                f.write(public_key)
            messagebox.showinfo("Success", "RSA keys generated and saved!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")

    def encrypt_action():
        try:
            if not (os.path.exists("public.pem") and os.path.exists("private.pem")):
                messagebox.showerror("Error", "Please generate RSA keys first!")
                return

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

            aes_key = get_random_bytes(16)
            with open("public.pem", "rb") as f:
                public_key = f.read()
            encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

            with open("aes_key.enc", "wb") as f:
                f.write(encrypted_aes_key)

            encrypt_file(file_path, output_path, aes_key, save_as_text, performance_tracker)
            messagebox.showinfo("Success", "File encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_action():
        try:
            if not (os.path.exists("private.pem") and os.path.exists("aes_key.enc")):
                messagebox.showerror("Error", "Missing private key or AES key!")
                return

            file_path = filedialog.askopenfilename(
                title="Select File to Decrypt",
                filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
            )
            if not file_path:
                return

            if not os.path.exists("file_metadata.txt"):
                messagebox.showerror("Error", "Metadata file not found!")
                return
                
            with open("file_metadata.txt", "r") as meta_file:
                original_extension = meta_file.read().strip()

            output_path = filedialog.asksaveasfilename(
                title="Save Decrypted File",
                defaultextension=original_extension,
                filetypes=[("All Files", "*.*")]
            )
            if not output_path:
                return

            is_text = messagebox.askyesno("Format", "Is the encrypted file in Base64 format?")

            with open("aes_key.enc", "rb") as f:
                encrypted_aes_key = f.read()

            with open("private.pem", "rb") as f:
                private_key = f.read()
                
            aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
            decrypt_file(file_path, output_path, aes_key, is_text, performance_tracker)
            messagebox.showinfo("Success", "File decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    # Menambahkan tombol-tombol
    tk.Button(button_frame, text="Generate RSA Keys", command=generate_keys_action, 
              width=30, bg="pink", fg="black").pack(pady=10)
    tk.Button(button_frame, text="Encrypt File", command=encrypt_action, 
              width=30, bg="lightblue", fg="black").pack(pady=10)
    tk.Button(button_frame, text="Decrypt File", command=decrypt_action, 
              width=30, bg="lightgreen", fg="black").pack(pady=10)

    # Label untuk tabel
    tk.Label(title_frame, text="Performance Tracking", font=('Helvetica', 12, 'bold')).pack(pady=(0, 10))
    
    # Pack tree dan scrollbar
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    root.mainloop()

if __name__ == "__main__":
    main()