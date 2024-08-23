from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
import os


def encrypt_file(file_name, key):
    fernet = Fernet(key)
    with open(file_name, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_name, "wb") as file:
        file.write(encrypted_data)


def decrypt_file(file_name, key):
    fernet = Fernet(key)
    with open(file_name, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_name, "wb") as file:
        file.write(decrypted_data)


def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def save_password(service, password, key):
    encrypted_password = encrypt_password(password, key)
    with open("C:\\users\\mzkwcim\\desktop\\passwords.txt", "a") as file:
        file.write(f"{service}: {encrypted_password.decode()}\n")


def load_passwords(key):
    if not os.path.exists("C:\\users\\mzkwcim\\desktop\\passwords.txt"):
        print("No passwords saved yet.")
        return

    with open("C:\\users\\mzkwcim\\desktop\\passwords.txt", "r") as file:
        for line in file.readlines():
            service, encrypted_password = line.strip().split(": ")
            try:
                decrypted_password = decrypt_password(encrypted_password.encode(), key)
                print(f"Service: {service}, Password: {decrypted_password}")
            except Exception as e:
                print(f"Error decrypting password for {service}: {str(e)}")


def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password


def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password


def main():
    salt_file = "c:\\users\\mzkwcim\\desktop\\salt.salt"

    if not os.path.exists(salt_file):
        print("Generating new salt...")
        salt = os.urandom(16)
        with open(salt_file, "wb") as file:
            file.write(salt)
    else:
        print("Loading existing salt...")
        with open(salt_file, "rb") as file:
            salt = file.read()

    password = input("Enter your master password: ")
    print("Generating encryption key...")
    key = generate_key_from_password(password, salt)

    passwords_file = "C:\\users\\mzkwcim\\desktop\\passwords.txt"

    if os.path.exists(passwords_file):
        print("Decrypting passwords file...")
        decrypt_file(passwords_file, key)

    try:
        while True:
            print("Menu options presented...")
            choice = input("What do you want to do?\n1. Save a new password\n2. Load passwords\n3. Exit\n")

            if choice == "1":
                service = input("Enter the service name: ")
                password = input("Enter the password: ")
                save_password(service, password, key)
                print(f"Password for {service} saved.\n")

            elif choice == "2":
                print("Stored passwords:")
                load_passwords(key)

            elif choice == "3":
                print("Encrypting passwords file and exiting...")
                encrypt_file(passwords_file, key)
                print("Goodbye!")
                break

            else:
                print(f"Invalid choice '{choice}', try again.\n")

    except KeyboardInterrupt:
        print("\nExiting and encrypting file...")
        encrypt_file(passwords_file, key)
        print("Goodbye!")


if __name__ == "__main__":
    main()
