import customtkinter as CTk
from  PIL import Image
from Crypto.Cipher import DES
import hashlib
import base64


class App(CTk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("460x700")
        self.title("шифровка текста")
        self.resizable(False, False)
        self.tabview = CTk.CTkTabview(self)
        self.tabview.pack(padx=20, pady=20)
        self.dec_frame = self.tabview.add("расшифровать")
        self.ec_frame = self.tabview.add("зашифровать")
        self.tabview.set("зашифровать")



        self.logo = CTk.CTkImage(dark_image=Image.open("logo.png"), size = (100,100))
        self.logo_lable = CTk.CTkLabel(master=self.tabview.tab("зашифровать"),text="",image=self.logo)
        self.logo_lable.grid(row=0, column=0)

        self.entry_password = CTk.CTkEntry(master=self.tabview.tab("зашифровать"), width=200)
        self.entry_password.grid(row=0,column=0, padx=(0,20) )

        self.entry_text = CTk.CTkTextbox(master=self.tabview.tab("зашифровать"), width=430, height=100)
        self.entry_text.grid(row=1, column=0, padx=(0, 20))

        self.encrypted_text = CTk.CTkTextbox(master=self.tabview.tab("зашифровать"), width=430, height=100)
        self.encrypted_text.grid(row=2, column=0, padx=(0, 20))

        self.btn_encryption =CTk.CTkButton(master=self.tabview.tab("зашифровать"), text="зашибровать",
                                           width=1, command=self.get_encryption)
        self.btn_encryption.grid(row=3,column=0)

        ##-----------------------------
        self.logo = CTk.CTkImage(dark_image=Image.open("logo.png"), size=(100, 100))
        self.logo_lable = CTk.CTkLabel(master=self.tabview.tab("расшифровать"), text="", image=self.logo)
        self.logo_lable.grid(row=0, column=0)

        self.entry_password_dec = CTk.CTkEntry(master=self.tabview.tab("расшифровать"), width=200)
        self.entry_password_dec.grid(row=0, column=0, padx=(0, 20))

        self.entry_text_dec = CTk.CTkTextbox(master=self.tabview.tab("расшифровать"), width=430, height=100)
        self.entry_text_dec.grid(row=1, column=0, padx=(0, 20))

        self.decrypted_text = CTk.CTkTextbox(master=self.tabview.tab("расшифровать"), width=430, height=100)
        self.decrypted_text.grid(row=2, column=0, padx=(0, 20))

        self.btn_encryption = CTk.CTkButton(master=self.tabview.tab("расшифровать"), text="расшифровать",
                                            width=1, command=self.get_decript)
        self.btn_encryption.grid(row=3, column=0)




    def get_encryption(self, *arg):
        key = self.entry_password.get()
        text = self.entry_text.get('1.0', 'end-1c')
        self.encrypted_text.delete('1.0', 'end-1c')
        self.encrypted_text.insert('1.0', GetEncrip(key, text))

    def get_decript(self,*args):
        key = self.entry_password_dec.get()
        text = self.entry_text_dec.get('1.0', 'end-1c')
        self.decrypted_text.delete('1.0', 'end-1c')
        self.decrypted_text.insert('1.0', GetDegript(key,text))


def GetEncrip(password,text):
    key= (hashlib.md5(password.encode('utf8')).hexdigest()[-8::]).encode()
    def pad(text):
        while len(text) % 8 != 0:
            text += b' '
        return text
    des = DES.new(key, DES.MODE_ECB)
    text = text.encode('utf8')
    padded_text = pad(text)
    encrypted_text = des.encrypt(padded_text)
    base64_str = base64.b64encode(encrypted_text)
    return base64_str

def GetDegript(password,encrypted_text):
    key = (hashlib.md5(password.encode('utf8')).hexdigest()[-8::]).encode()
    des = DES.new(key, DES.MODE_ECB)
    encrypted_text = encrypted_text.encode()
    text = base64.b64decode(encrypted_text)
    data = des.decrypt(text)
    print(data.decode('utf8'))
    return data.decode('utf8')

if __name__ == "__main__":
    app = App()
    app.mainloop()