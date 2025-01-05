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
        self.tree.insert('', 'end', values=( 
            record['timestamp'],
            record['operation'],
            record['file_size_mb'],
            record['duration_seconds'],
            record['memory_usage_mb'],
            record['cpu_percent']
        ))

# AES Enkripsi dan Dekripsi
def aes_encrypt_file(file_path, output_path, tracker=None):
    try:
        start_time = time.time()
        file_size = os.path.getsize(file_path)
        
        # Generate AES key and IV
        aes_key = get_random_bytes(32)  # AES-256
        iv = get_random_bytes(16)
        
        # Save AES key and IV
        with open("aes_key.bin", "wb") as key_file:
            key_file.write(aes_key)
            key_file.write(iv)
        
        # Create cipher
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # Read and encrypt file
        with open(file_path, 'rb') as f:
            data = f.read()
            # Add padding if needed
            if len(data) % 16 != 0:
                padding_length = 16 - (len(data) % 16)
                data += bytes([padding_length]) * padding_length
            
        # Include original file extension in the encrypted data
        file_extension = os.path.splitext(file_path)[1].encode('utf-8')
        ext_length = len(file_extension)
        ciphertext = cipher.encrypt(data)
        
        with open(output_path, 'wb') as f:
            # Save extension length, extension, and ciphertext
            f.write(ext_length.to_bytes(1, 'big'))
            f.write(file_extension)
            f.write(ciphertext)
        
        end_time = time.time()
        if tracker:
            tracker.track_operation('AES Encryption', file_size, start_time, end_time)
        
        return True
    except Exception as e:
        raise Exception(f"AES encryption failed: {str(e)}")

def aes_decrypt_file(file_path, output_path, tracker=None):
    try:
        start_time = time.time()
        file_size = os.path.getsize(file_path)
        
        # Read AES key and IV
        with open("aes_key.bin", "rb") as key_file:
            aes_key = key_file.read(32)
            iv = key_file.read(16)
        
        # Read encrypted file
        with open(file_path, 'rb') as f:
            ext_length = int.from_bytes(f.read(1), 'big')
            file_extension = f.read(ext_length).decode('utf-8')
            ciphertext = f.read()
        
        # Create cipher
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # Decrypt data
        decrypted_data = cipher.decrypt(ciphertext)
        
        # Remove padding
        if len(decrypted_data) > 0:
            padding_length = decrypted_data[-1]
            if padding_length < 16:
                decrypted_data = decrypted_data[:-padding_length]
        
        # Save decrypted file with the original extension
        output_path += file_extension
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        end_time = time.time()
        if tracker:
            tracker.track_operation('AES Decryption', file_size, start_time, end_time)
        
        return True
    except Exception as e:
        raise Exception(f"AES decryption failed: {str(e)}")
        
# RSA Enkripsi dan Dekripsi
def rsa_encrypt_file(file_path, output_path, tracker):
    try:
        start_time = time.time()  # Tambahkan ini di awal fungsi
        
        with open("public_key.pem", "rb") as f:
            public_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(public_key)
        
        # Get file extension
        file_extension = os.path.splitext(file_path)[1].encode('utf-8')
        ext_length = len(file_extension)
        
        # Read file data
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Generate random AES key for file encryption
        session_key = get_random_bytes(16)
        
        # Encrypt the session key with RSA
        encrypted_session_key = cipher.encrypt(session_key)
        
        # Use AES to encrypt the file data
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        
        # Pad the data
        padding_length = 16 - (len(file_data) % 16)
        padded_data = file_data + bytes([padding_length] * padding_length)
        
        # Encrypt with AES
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # Write everything to the output file
        with open(output_path, 'wb') as f:
            f.write(len(encrypted_session_key).to_bytes(2, 'big'))
            f.write(encrypted_session_key)
            f.write(cipher_aes.iv)
            f.write(ext_length.to_bytes(1, 'big'))
            f.write(file_extension)
            f.write(encrypted_data)
        
        end_time = time.time()
        if tracker:
            tracker.track_operation('RSA Encrypt', len(file_data), start_time, end_time)

    except Exception as e:
        messagebox.showerror("Error", f"RSA encryption failed: {e}")

def rsa_decrypt_file(file_path, output_path, tracker):
    try:
        start_time = time.time()  # Tambahkan ini di awal fungsi
        
        with open("private_key.pem", "rb") as f:
            private_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(private_key)

        with open(file_path, 'rb') as f:
            # Read encrypted session key length
            session_key_length = int.from_bytes(f.read(2), 'big')
            # Read and decrypt session key
            encrypted_session_key = f.read(session_key_length)
            session_key = cipher.decrypt(encrypted_session_key)
            
            # Read IV
            iv = f.read(16)
            
            # Read file extension
            ext_length = int.from_bytes(f.read(1), 'big')
            file_extension = f.read(ext_length).decode('utf-8')
            
            # Read encrypted data
            encrypted_data = f.read()

        # Decrypt data with AES
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted_data = cipher_aes.decrypt(encrypted_data)
        
        # Remove padding
        padding_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_length]
        
        # Write decrypted data with original extension
        with open(f"{output_path}{file_extension}", 'wb') as f:
            f.write(decrypted_data)
        
        end_time = time.time()
        if tracker:
            tracker.track_operation('RSA Decrypt', len(decrypted_data), start_time, end_time)

    except Exception as e:
        messagebox.showerror("Error", f"RSA decryption failed: {e}")

# Generate and Reset RSA Keys
def generate_rsa_keys(tracker, status_label):
    try:
        start_time = time.time()
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open("private_key.pem", "wb") as f:
            f.write(private_key)
        with open("public_key.pem", "wb") as f:
            f.write(public_key)

        status_label.config(text="RSA keys are active", fg="green")
        end_time = time.time()
        if tracker:
            tracker.track_operation('Generate RSA Keys', 0, start_time, end_time)

        messagebox.showinfo("Success", "RSA keys generated successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate RSA keys: {str(e)}")

def reset_rsa_keys(status_label):
    try:
        if os.path.exists("private_key.pem"):
            os.remove("private_key.pem")
        if os.path.exists("public_key.pem"):
            os.remove("public_key.pem")
        
        status_label.config(text="RSA keys are not active", fg="red")
        messagebox.showinfo("Success", "RSA keys have been reset!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to reset RSA keys: {str(e)}")

# Hybrid Enkripsi dan Dekripsi
def hybrid_encrypt_file(file_path, output_path, tracker):
    try:
        start_time = time.time()  # Tambahkan tracking waktu di awal
        
        with open("public_key.pem", "rb") as f:
            public_key = RSA.import_key(f.read())

        # Get file extension
        file_extension = os.path.splitext(file_path)[1].encode('utf-8')
        ext_length = len(file_extension)

        # Read file data
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # AES encryption
        aes_key = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        
        ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

        # Encrypt AES key with RSA public key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        with open(output_path, 'wb') as f:
            # Write all components
            f.write(len(encrypted_aes_key).to_bytes(2, 'big'))
            f.write(encrypted_aes_key)
            f.write(cipher_aes.nonce)
            f.write(tag)
            # Write file extension information
            f.write(ext_length.to_bytes(1, 'big'))
            f.write(file_extension)
            # Write encrypted data
            f.write(ciphertext)
        
        end_time = time.time()
        if tracker:
            tracker.track_operation('Hybrid Encrypt', len(file_data), start_time, end_time)

    except Exception as e:
        messagebox.showerror("Error", f"Hybrid encryption failed: {e}")

def hybrid_decrypt_file(file_path, output_path, tracker):
    try:
        start_time = time.time()  # Tambahkan tracking waktu di awal
        
        with open("private_key.pem", "rb") as f:
            private_key = RSA.import_key(f.read())

        with open(file_path, 'rb') as f:
            # Read encrypted AES key info
            key_length = int.from_bytes(f.read(2), 'big')
            encrypted_aes_key = f.read(key_length)
            
            # Read AES parameters
            nonce = f.read(16)
            tag = f.read(16)
            
            # Read file extension
            ext_length = int.from_bytes(f.read(1), 'big')
            file_extension = f.read(ext_length).decode('utf-8')
            
            # Read encrypted data
            ciphertext = f.read()

        # Decrypt AES key with RSA private key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Decrypt the file with AES
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        file_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Write decrypted file with original extension
        with open(f"{output_path}{file_extension}", 'wb') as f:
            f.write(file_data)

        end_time = time.time()
        if tracker:
            tracker.track_operation('Hybrid Decrypt', len(file_data), start_time, end_time)

    except Exception as e:
        messagebox.showerror("Error", f"Hybrid decryption failed: {e}")
        
def main():
    root = tk.Tk()
    root.title("Multi-Algorithm Encryption Program")
    root.geometry("800x600")

    button_frame = tk.Frame(root, padx=20, pady=20)
    button_frame.pack(fill='x')
    
    table_frame = tk.Frame(root, padx=20)
    table_frame.pack(fill='both', expand=True)
    
    tree = ttk.Treeview(table_frame)
    tree['columns'] = ('Timestamp', 'Operation', 'File Size (MB)', 'Duration (s)', 'Memory (MB)', 'CPU (%)')
    
    for col in tree['columns']:
        tree.column(col, width=100)
        tree.heading(col, text=col)
    tree.column('#0', width=0, stretch=tk.NO)
    
    scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    
    tracker = PerformanceTracker(tree)
    
    algorithm_var = tk.StringVar(value="hybrid")
    ttk.Label(button_frame, text="Select Algorithm:").pack()
    ttk.Radiobutton(button_frame, text="AES", value="aes", variable=algorithm_var).pack()
    ttk.Radiobutton(button_frame, text="RSA", value="rsa", variable=algorithm_var).pack()
    ttk.Radiobutton(button_frame, text="Hybrid", value="hybrid", variable=algorithm_var).pack()

    status_label = tk.Label(button_frame, text="RSA keys are not active", fg="red")
    status_label.pack(pady=5)

    def generate_keys_action():
        generate_rsa_keys(tracker, status_label)

    def reset_keys_action():
        reset_rsa_keys(status_label)

    def encrypt_action():
        try:
            algorithm = algorithm_var.get()
            
            file_path = filedialog.askopenfilename(title="Select file to encrypt")
            if not file_path:
                return
                
            output_path = filedialog.asksaveasfilename(
                title="Save encrypted file",
                defaultextension=".enc"
            )
            if not output_path:
                return

            if algorithm == "aes":
                aes_encrypt_file(file_path, output_path, tracker)
            elif algorithm == "rsa":
                rsa_encrypt_file(file_path, output_path, tracker)
            else:  # hybrid
                hybrid_encrypt_file(file_path, output_path, tracker)
                
            messagebox.showinfo("Success", "File encrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_action():
        try:
            algorithm = algorithm_var.get()
            
            file_path = filedialog.askopenfilename(title="Select file to decrypt")
            if not file_path:
                return
                
            output_path = filedialog.asksaveasfilename(title="Save decrypted file")
            if not output_path:
                return
            if algorithm == "aes":
                aes_decrypt_file(file_path, output_path, tracker)
            elif algorithm == "rsa":
                rsa_decrypt_file(file_path, output_path, tracker)
            else:  # hybrid
                hybrid_decrypt_file(file_path, output_path, tracker)
                
            messagebox.showinfo("Success", "File decrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    ttk.Button(button_frame, text="Generate RSA Keys", command=generate_keys_action).pack(pady=5)
    ttk.Button(button_frame, text="Reset RSA Keys", command=reset_keys_action).pack(pady=5)
    ttk.Button(button_frame, text="Encrypt File", command=encrypt_action).pack(pady=5)
    ttk.Button(button_frame, text="Decrypt File", command=decrypt_action).pack(pady=5)
    
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    root.mainloop()

if __name__ == "__main__":
    main()
