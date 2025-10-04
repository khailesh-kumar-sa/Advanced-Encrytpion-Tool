import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class AESCipher:
    def __init__(self, password: str):
        # Derive a strong 256-bit key from password using SHA-256
        self.key = hashlib.sha256(password.encode()).digest()

    def encrypt_file(self, input_file: str, output_file: str):
        with open(input_file, 'rb') as f:
            data = f.read()
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = cipher.iv
        # Save IV + ciphertext to output file
        with open(output_file, 'wb') as f:
            f.write(iv + ct_bytes)
        print(f"File encrypted successfully and saved to: {output_file}")

    def decrypt_file(self, input_file: str, output_file: str):
        with open(input_file, 'rb') as f:
            iv = f.read(16)  # AES block size = 16 bytes
            ct = f.read()
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        data = unpad(cipher.decrypt(ct), AES.block_size)
        with open(output_file, 'wb') as f:
            f.write(data)
        print(f"File decrypted successfully and saved to: {output_file}")

def main():
    print("===== AES-256 File Encryption/Decryption Tool =====")
    password = input("Enter encryption/decryption password: ")
    aes = AESCipher(password)

    while True:
        choice = input("\nChoose an option:\n1. Encrypt a file\n2. Decrypt a file\n0. Exit\n> ").strip()
        if choice == '1':
            input_path = input("Enter path to file to encrypt: ").strip()
            if not os.path.isfile(input_path):
                print("Invalid file path.")
                continue
            output_path = input("Enter output encrypted file path: ").strip()
            aes.encrypt_file(input_path, output_path)
        elif choice == '2':
            input_path = input("Enter path to file to decrypt: ").strip()
            if not os.path.isfile(input_path):
                print("Invalid file path.")
                continue
            output_path = input("Enter output decrypted file path: ").strip()
            try:
                aes.decrypt_file(input_path, output_path)
            except ValueError:
                print("Decryption failed. Wrong password or corrupted file.")
        elif choice == '0':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
