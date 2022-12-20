__author__ = "Abenezer Samuel   ATR/2809/11 "
"""This is a CNS course project to implement the Symmetric Encryption methods"""


from tkinter import *
from tkinter import ttk
from OTP import *
from TripleDES import triple_des,base64
from AES import *


class Root(Tk):
    """The Graphical user Interface for the program"""

    def __init__(self):
        super(Root, self).__init__()
        self.title("Symmetric Encription/Dectypiton")
        self.geometry("800x600")
        self.configure(background='#d2d2d2')
        self.resizable(0,0)
        self.minsize(640, 400)
        #self.background("")
        self.algorithms = ["OTP", "3DES", "ASE"]
        self.cipher = ""
        self.decipher = ""

        #Right Frames

        #Row 1 colomun 1
        self.encription_frame =LabelFrame(self, text="Encryption",width=40, height= 10, background="#d2d2d2")
        self.encription_frame.grid(row=0,column=0, padx=20, pady=0)
        self.frame_title = Label(self.encription_frame, text="Message to Encrypt",font="sans 14 bold", bg="#d2d2d2")
        self.frame_title.pack(side=TOP)
        self.msgbox = Text(self.encription_frame, width=40, height=10,)
        self.msgbox.pack()
        
        #Row2 column 1
        self.EKey_frame = LabelFrame(self,width=400, height= 10, background="#d2d2d2")
        self.EKey_frame.grid(row=1,column=0, padx=0, pady=0)
        self.label = Label(self.EKey_frame, text="Encryption Key", fg="Red", bg="#d2d2d2")
        self.label.grid(row=0,column=0)
        self.EncriptionKey = Entry(self.EKey_frame,width=32)
        self.EncriptionKey.grid(row=0,column=1, padx=20)
        self.encrypt_btn = Button(self.EKey_frame,text="Encrypt", fg="white", bg="#003333", command=self.encrypt)
        self.encrypt_btn.grid(row=2, column=0, padx= 0, pady= 20)
        self.Copyencrypt_btn = Button(self.EKey_frame,text="Copy Encryption", fg="white", bg="#660000", command=self.copy)
        self.Copyencrypt_btn.grid(row=2, column=1, padx= 0, pady= 20)

        #Row3 column 1
        self.Encrypted_text = LabelFrame(self, borderwidth=0,width=40, height= 10,  background="#d2d2d2")
        self.Encrypted_text.grid(row=2,column=0, padx=0, pady=0)
        self.h_s = Scrollbar(self.Encrypted_text, orient='horizontal')
        self.h_s.pack(side=BOTTOM,fill=X)
        self.Ciphered_text = Text(self.Encrypted_text, width=40, height=10,wrap = NONE, xscrollcommand=self.h_s.set)
        self.Ciphered_text.pack()

        #Row1 column 2
        self.Decryption_Frame = LabelFrame(self, text="Decryption", width=40, height= 10,  background="#d2d2d2")
        self.Decryption_Frame.grid(row=0,column=1, padx=20, pady=0)
        self.label = Label(self.Decryption_Frame, text="Message to Decrypt",font='sans 14 bold', bg="#d2d2d2")
        self.label.pack(side=TOP)
        self.h_s = Scrollbar(self.Decryption_Frame, orient='horizontal')
        self.h_s.pack(side=BOTTOM,fill=X)
        self.msg_to_decrypt = Text(self.Decryption_Frame, width=40, height=10,wrap= NONE,xscrollcommand=self.h_s.set)
        self.msg_to_decrypt.pack()

        #Row2 column2
        self.DK_Frame = LabelFrame(self,width=400, height= 10, background="#d2d2d2")
        self.DK_Frame.grid(row=1,column=1, padx=2, pady=0)
        self.label = Label(self.DK_Frame, text="Decription Key", fg="Red",borderwidth=0, bg="#d2d2d2")
        self.label.grid(row=0,column=0)
        self.DecriptionKey = Entry(self.DK_Frame,width=32)
        self.DecriptionKey.grid(row=0,column=1, padx=20)
        self.decrypt_btn = Button(self.DK_Frame,text="Decrypt", fg="white", bg="#003333", command=self.deycrypt)
        self.decrypt_btn.grid(row=2, column=0, padx= 0, pady= 20)
        self.Pastedecrypt_btn = Button(self.DK_Frame,text="Paste Decryption_key", fg="white", bg="#660000", command=self.paste)
        self.Pastedecrypt_btn.grid(row=2, column=1, padx= 0, pady= 20)
        
        #Row3 column 2
        self.Decrypted_text = LabelFrame(self, borderwidth=0,width=40, height= 10, background="#d2d2d2")
        self.Decrypted_text.grid(row=2,column=1, padx=20, pady=0)
        self.Deciphered_msg = Text(self.Decrypted_text, width=40, height=10)
        self.Deciphered_msg.config(state=DISABLED)
        self.Deciphered_msg.pack()


        #Bottom of screen
        self.Algo_frame = LabelFrame(self,width=400, height= 20, background="#d2d2d2")
        self.Algo_frame.grid(row=3,column=0, padx=10, pady=10)
        self.label = Label(self.Algo_frame,width=20, text="Choose Algorithms", bg="#d2d2d2")
        self.label.grid(row=0,column=0,padx=0)
        self.combo_box = ttk.Combobox(self.Algo_frame,value=self.algorithms, width=30)
        self.combo_box.grid(row=0,column=1, padx=20)
        self.clear_btn = Button(self.Algo_frame, text="Clear", fg="white", bg="Green", command=self.clear)
        self.clear_btn.grid(row=2, column=1, padx=20)

    def clear(self):
        """Clears all the fields.
        """
        self.DecriptionKey.delete(0, END)
        self.EncriptionKey.delete(0,END)
        self.cipher, self.decipher = 0, 0
        self.msgbox.delete(1.0,END)
        self.Ciphered_text.config(state=NORMAL)
        self.Ciphered_text.delete(1.0,END)
        self.msg_to_decrypt.delete(1.0,END)
        self.Deciphered_msg.config(state=NORMAL)
        self.Deciphered_msg.delete(1.0,END)


    def copy(self):
        """Takes saves the encryption key"""
        self.cipher = self.EncriptionKey.get()
        

    def paste(self):
        """Puts the Encryption key in Decription box"""
        self.decipher = self.cipher
        self.DecriptionKey.delete(0,END)
        self.DecriptionKey.insert(INSERT,self.decipher)

    def encrypt(self):
        """Generates an encrypted message based on the chosen Algorithm using the Key
        """
        plain_text = self.msgbox.get(1.0,END)
        plain_text = plain_text.strip()
        key = self.EncriptionKey.get()
        Algorithm = self.combo_box.get()
        self.Ciphered_text.config(state=NORMAL)
        self.msg_to_decrypt.config(state=NORMAL)
        self.Ciphered_text.delete(1.0, 'end-1c')
        ciphered = ''
        
        if Algorithm == "OTP":
            self.Ciphered_text.delete(1.0, END)
            ciphered = Ontime(plain_text,key)

        elif Algorithm == "3DES":
            data = bytes(plain_text,"utf-8")
            CBC = 0
            try:
                k = triple_des(key, CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=2)
                ciphered =base64.b64encode(k.encrypt(data))
            except Exception as e:
                self.Ciphered_text.insert(END,e)
            pass
        elif Algorithm == "ASE":
            try:
                ciphered = encrypt_aes(plain_text,key)
            except Exception as e:
                self.Ciphered_text.insert(END,e)
            pass

        self.Ciphered_text.insert(INSERT, ciphered)
        self.Ciphered_text.config(state=DISABLED)

    def deycrypt(self):
        """Generates a plain_text form an encrypted text based on the chosen Algorithm and Key
        """
        self.Deciphered_msg.delete(1.0, END)
        plain_text = ''
        ciphered = self.msg_to_decrypt.get(1.0, 'end-1c')
        ciphered = ciphered.strip()
        Algorithm = self.combo_box.get()
        key = self.EncriptionKey.get()
        self.Deciphered_msg.config(state=NORMAL)
        self.Deciphered_msg.delete(1.0, 'end-1c')
        if Algorithm == "OTP":
            plain_text =base64.b64decode(Ontime( base64.b64decode(ciphered).decode('utf-8'),key))
        elif Algorithm == "3DES":
            try:
                data =base64.b64decode(ciphered)
                CBC = 0
                k = triple_des(key, CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=2)
                plain_text = k.decrypt(data)
            except Exception as e:
                self.Deciphered_msg.insert(END,e)
                pass
        elif Algorithm == "ASE":
                try:
                    plain_text = decrypt_aes(ciphered,key)
                except Exception as e:
                    self.Deciphered_msg.insert(END,e)
                pass

        self.Deciphered_msg.insert(INSERT,plain_text)
        self.Deciphered_msg.config(state=DISABLED)      
        



if __name__ == "__main__":
    window = Root()
    window.mainloop()
