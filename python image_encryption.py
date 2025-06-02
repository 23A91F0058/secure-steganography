#!/usr/bin/env python
from __future__ import division, print_function, unicode_literals

import os
import random
import hashlib
import binascii
import numpy as np
from tkinter import *
from tkinter import filedialog as tkFileDialog
from tkinter import messagebox as tkMessageBox
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ----------------- Helper Functions ---------------------#
def load_image(name):
    return Image.open(name)

def save_image(image, filename):
    image.save(filename)

# ---------------- Encryption Functions ----------------- #
def generate_secret(size):
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))

    for x in range(0, 2 * width, 2):
        for y in range(0, 2 * height, 2):
            color = np.random.randint(0, 256, 3)
            new_secret_image.putpixel((x, y), tuple(color))
            new_secret_image.putpixel((x + 1, y), tuple(255 - color))
            new_secret_image.putpixel((x, y + 1), tuple(255 - color))
            new_secret_image.putpixel((x + 1, y + 1), tuple(color))
    return new_secret_image

def level_one_encrypt(image_name):
    image = load_image(image_name)
    size = image.size
    secret_image = generate_secret(size)
    save_image(secret_image, "secret.jpeg")

    ciphered_image = generate_ciphered_image(secret_image, image)
    save_image(ciphered_image, "2-share_encrypt.jpeg")

def generate_ciphered_image(secret_image, prepared_image):
    width, height = prepared_image.size
    ciphered_image = Image.new(mode="RGB", size=(width * 2, height * 2))

    for x in range(0, width * 2, 2):
        for y in range(0, height * 2, 2):
            sec = secret_image.getpixel((x, y))
            msg = prepared_image.getpixel((x // 2, y // 2))
            color = [(msg[i] + sec[i]) % 256 for i in range(3)]
            ciphered_image.putpixel((x, y), tuple(color))
            ciphered_image.putpixel((x + 1, y), tuple(255 - np.array(color)))
            ciphered_image.putpixel((x, y + 1), tuple(255 - np.array(color)))
            ciphered_image.putpixel((x + 1, y + 1), tuple(color))
    return ciphered_image

# AES Encryption/Decryption
def encrypt(image_name, password):
    with open(image_name, 'rb') as file:
        plaintext = file.read()

    # Pad plaintext to AES block size
    plaintext = pad(plaintext, AES.block_size)

    iv = b'This is an IV456'  # Ensure IV is 16 bytes
    cipher = AES.new(password, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)

    with open(image_name + '.enc', 'wb') as file:
        file.write(ciphertext)

    level_one_encrypt(image_name)
    print("Encryption complete.")

def generate_image_back(secret_image, ciphered_image):
    width, height = secret_image.size[0] // 2, secret_image.size[1] // 2
    new_image = Image.new(mode="RGB", size=(width, height))

    for x in range(0, width * 2, 2):
        for y in range(0, height * 2, 2):
            sec = secret_image.getpixel((x, y))
            cipher = ciphered_image.getpixel((x, y))
            color = [(cipher[i] - sec[i]) % 256 for i in range(3)]
            new_image.putpixel((x // 2, y // 2), tuple(color))
    return new_image

def decrypt(cipher_name, password):
    secret_image = Image.open("secret.jpeg")
    ciphered_image = Image.open("2-share_encrypt.jpeg")
    new_image = generate_image_back(secret_image, ciphered_image)
    new_image.save("2-share_decrypt.jpeg")
    print("Decryption complete.")

    with open(cipher_name, 'rb') as file:
        ciphertext = file.read()

    iv = b'This is an IV456'
    cipher = AES.new(password, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # Save the decrypted image
    with open("decrypted_image.png", 'wb') as file:
        file.write(plaintext)

# ---------------- GUI Functions ---------------- #
def pass_alert():
    tkMessageBox.showinfo("Password Alert", "Please enter a password.")

def image_open():
    enc_pass = passg.get()
    if not enc_pass:
        pass_alert()
        return

    password = hashlib.sha256(enc_pass.encode()).digest()
    filename = tkFileDialog.askopenfilename(title="Select an image to encrypt")
    if filename:
        encrypt(filename, password)
        tkMessageBox.showinfo("Success", f"Encrypted Image: {filename}.enc")

def cipher_open():
    dec_pass = passg.get()
    if not dec_pass:
        pass_alert()
        return

    password = hashlib.sha256(dec_pass.encode()).digest()
    filename = tkFileDialog.askopenfilename(title="Select an encrypted file to decrypt")
    if filename:
        decrypt(filename, password)
        tkMessageBox.showinfo("Success", f"Decrypted Image: {filename}.dec")

# ---------------- GUI ---------------- #
class App:
    def __init__(self, master):
        global passg
        master.title("Image Encryption")
        Label(master, text="Enter Encrypt/Decrypt Password:").pack()
        passg = Entry(master, show="*", width=20)
        passg.pack()

        self.encrypt_btn = Button(master, text="Encrypt", command=image_open, width=25, height=2)
        self.encrypt_btn.pack(side=LEFT, padx=10, pady=10)
        self.decrypt_btn = Button(master, text="Decrypt", command=cipher_open, width=25, height=2)
        self.decrypt_btn.pack(side=RIGHT, padx=10, pady=10)

# Main
if __name__ == "__main__":
    root = Tk()
    app = App(root)
    root.mainloop()
