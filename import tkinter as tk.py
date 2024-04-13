import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder, Name
from cryptography.x509.oid import NameOID
from cryptography.x509 import NameAttribute
from datetime import datetime, timedelta
from cryptography import x509

class DigitalSignatureApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Digital Signature App")
        self.master.configure(bg='#E7CA91')  # set background color

        self.custom_font = ('Helvetica', 12)  # define custom font

        self.button_color = '#00D75E'  # button color
        self.entry_bg = "#FFFFFF"  # entry background color
        self.entry_border_color = "#A9A9A9"  # entry border color
        self.entry_border_width = 2  # entry border width
        self.entry_border_radius = 5  # entry border radius
        self.focus_bg = "#90EE90"  # background color when focused

        self.file_label = tk.Label(master, text="Выберите файл:", font=('Segoe UI', 12, 'bold'), bg='#E7CA91')
        self.file_label.pack(pady=3)

        self.file_button = tk.Button(master, text="Выбрать файл", command=self.choose_file, font=self.custom_font, bg=self.button_color)
        self.file_button.pack(pady=3)

        self.generate_button = tk.Button(master, text="Создать подпись", command=self.generate_signature, font=self.custom_font, bg=self.button_color)
        self.generate_button.pack(pady=3)

        self.verify_button = tk.Button(master, text="Проверить подпись", command=self.verify_signature, font=self.custom_font, bg=self.button_color)
        self.verify_button.pack(pady=3)

        self.result_label = tk.Label(master, text="", font=self.custom_font, bg='#E7CA91')
        self.result_label.pack(pady=3)

        input_frame = tk.Frame(master, bg='#E7CA91')
        input_frame.pack(pady=10)

        self.name_label = tk.Label(input_frame, text="Имя:", font=('Segoe UI', 12), bg='#E7CA91')
        self.name_label.grid(row=0, column=0, padx=5, pady=3)

        self.name_entry = tk.Entry(input_frame, font=('Segoe UI', 12), bd=0, relief=tk.GROOVE, bg=self.entry_bg, highlightbackground=self.entry_border_color, highlightthickness=self.entry_border_width)
        self.name_entry.grid(row=0, column=1, padx=5, pady=3)
        self.name_entry.bind("<FocusIn>", lambda event: self.name_entry.config(bg=self.focus_bg))
        self.name_entry.bind("<FocusOut>", lambda event: self.name_entry.config(bg=self.entry_bg))

        self.surname_label = tk.Label(input_frame, text="Фамилия:", font=('Segoe UI', 12), bg='#E7CA91')
        self.surname_label.grid(row=1, column=0, padx=5, pady=3)

        self.surname_entry = tk.Entry(input_frame, font=('Segoe UI', 12), bd=0, relief=tk.GROOVE, bg=self.entry_bg, highlightbackground=self.entry_border_color, highlightthickness=self.entry_border_width)
        self.surname_entry.grid(row=1, column=1, padx=5, pady=3)
        self.surname_entry.bind("<FocusIn>", lambda event: self.surname_entry.config(bg=self.focus_bg))
        self.surname_entry.bind("<FocusOut>", lambda event: self.surname_entry.config(bg=self.entry_bg))

        self.organization_label = tk.Label(input_frame, text="Организация:", font=('Segoe UI', 12), bg='#E7CA91')
        self.organization_label.grid(row=2, column=0, padx=5, pady=3)

        self.organization_entry = tk.Entry(input_frame, font=('Segoe UI', 12), bd=0, relief=tk.GROOVE, bg=self.entry_bg, highlightbackground=self.entry_border_color, highlightthickness=self.entry_border_width)
        self.organization_entry.grid(row=2, column=1, padx=5, pady=3)
        self.organization_entry.bind("<FocusIn>", lambda event: self.organization_entry.config(bg=self.focus_bg))
        self.organization_entry.bind("<FocusOut>", lambda event: self.organization_entry.config(bg=self.entry_bg))

        self.generate_certificate_button = tk.Button(master, text="Создать сертификат", command=self.generate_certificate, font=self.custom_font, bg=self.button_color, bd=2, relief=tk.GROOVE)
        self.generate_certificate_button.pack(pady=10)

    def choose_file(self):
        self.file_path = filedialog.askopenfilename()
        self.file_label.config(text="Выбранный файл: " + self.file_path)

    def generate_signature(self):
        if not hasattr(self, 'file_path'):
            messagebox.showerror("Ошибка", "Пожалуйста, выберите файл.")
            return

        # Генерация ключевой пары
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Сохранение ключей в файлы
        with open("private_key.pem", "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        with open("public_key.pem", "wb") as key_file:
            key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        # Чтение файла и создание подписи
        with open(self.file_path, "rb") as file:
            data = file.read()

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Сохранение подписи в файл
        with open(self.file_path + ".sig", "wb") as signature_file:
            signature_file.write(signature)

        messagebox.showinfo("Успех", "Подпись успешно создана.")

    def verify_signature(self):
        if not hasattr(self, 'file_path'):
            messagebox.showerror("Ошибка", "Пожалуйста, выберите файл.")
            return

        try:
            with open("public_key.pem", "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )

            with open(self.file_path, "rb") as file:
                data = file.read()

            with open(self.file_path + ".sig", "rb") as signature_file:
                signature = signature_file.read()

            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            messagebox.showinfo("Результат", "Подпись верна.")
        except Exception as e:
            messagebox.showerror("Ошибка", "Подпись недействительна: " + str(e))

    def generate_certificate(self):
        name = self.name_entry.get()
        surname = self.surname_entry.get()
        organization = self.organization_entry.get()

        if not name or not surname or not organization:
            messagebox.showerror("Ошибка", "Пожалуйста, заполните все поля.")
            return

        # Генерация ключевой пары
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Создание сертификата
        builder = CertificateBuilder()
        builder = builder.subject_name(
            Name([
                NameAttribute(NameOID.COMMON_NAME, name + " " + surname),
                NameAttribute(NameOID.ORGANIZATION_NAME, organization)
            ])
        )
        builder = builder.issuer_name(
            Name([
                NameAttribute(NameOID.COMMON_NAME, name + " " + surname),
                NameAttribute(NameOID.ORGANIZATION_NAME, organization)
            ])
        )
        builder = builder.public_key(public_key)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))

        cert = builder.sign(private_key, hashes.SHA256(), default_backend())

        # Сохранение сертификата в файл
        with open("certificate.crt", "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

        messagebox.showinfo("Успех", "Сертификат успешно создан.")

def main():
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
