import os
import PySimpleGUI as sg
from cryptography.fernet import Fernet

def runEncrypted(input_file):
    if not input_file:
        sg.popup_error("Please choose a file for encryption.")
        return None
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    with open(input_file, 'rb') as file:
        plaintext = file.read()
    encrypted_data = cipher_suite.encrypt(plaintext)
    output_file = f"{os.path.splitext(input_file)[0]}_encrypted.txt"
    with open(output_file, 'wb') as file:
        file.write(encrypted_data)
    key_file = f"{os.path.splitext(output_file)[0]}_key.txt"
    with open(key_file, 'wb') as key_file:
        key_file.write(key)
    window['key_encrypted'].update(key)
    window['encrypted_txt'].update(value=encrypted_data)
    return key
def runDecrypted(input_file, key_file):
    if not input_file or not key_file:
        sg.popup_error("Please choose a file for decryption and provide a decryption key.")
        return None
    with open(key_file, 'rb') as key_file:
        key = key_file.read()
    cipher_suite = Fernet(key)
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    output_file = f"{os.path.splitext(input_file)[0]}_decrypted.txt"
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(decrypted_data.decode('utf-8'))
    window['decrypt_cipher_txt'].update(value=decrypted_data.decode("utf-8"))
    return decrypted_data
def reset():
    window['BrowseInEn'].update('')
    window['key_encrypted'].update('')
    window['encrypted_txt'].update('')
    window['BrowseInDe'].update('')
    window['key_decrypted'].update('')
    window['decrypt_cipher_txt'].update('')
# design layout
sg.theme('Dark Blue17')
Font = ("prompt", 12)
FontHead = ("prompt", 16, "bold")
layout = [
    [sg.Frame("AES Encryption", font=FontHead, layout=[
        [sg.Text("Plaintext", font=Font), sg.Input(readonly=True, key='BrowseInEn'), sg.FileBrowse(key='encryption_input', font=Font), sg.Button("Encrypted", font=Font)],
        [sg.Text("Key Encryption", font=Font), sg.Input(size=(50, 1), key='key_encrypted', readonly=True)],
        [sg.Text("Encryption output", font=Font), sg.Multiline(size=(60, 4), key='encrypted_txt')]
    ])],
    [sg.Frame("AES Decryption", font=FontHead, layout=[
        [sg.Text("Cipher ->", font=Font), sg.Input(readonly=True, key='BrowseInDe'), sg.FileBrowse(key='decryption_input', font=Font), sg.Button("Decrypted", font=Font)],
        [sg.Text("Key Decryption", font=Font), sg.Input(size=(50, 1), key='key_decrypted', readonly=True), sg.FileBrowse(key='key_input', font=Font)],
        [sg.Text("Decryption output", font=Font), sg.Multiline(size=(60, 4), key='decrypt_cipher_txt')]
    ])],
    [sg.Text("", size=(60, 1), justification="right"), sg.Button("Reset", font=Font), sg.Button("Exit", font=Font)]
]
window = sg.Window('AES Encryption/Decryption - K0BiMaChi ', layout, resizable=True)
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit':
        break
    elif event == 'Encrypted':
        input_file = values['encryption_input']
        runEncrypted(input_file)
    elif event == 'Decrypted':
        input_file = values['decryption_input']
        key_file = values['key_input']
        decrypted_data = runDecrypted(input_file, key_file)
    elif event == 'Reset':
        reset()
window.close()
