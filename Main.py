import PySimpleGUI as sg
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import tkinter as tk

# Function to create a centered text element
def centered_text(text, size=(32, 1), font=('prompt 32 bold')):
    return sg.Text(text, size=size, font=font, justification='center')

# Function to generate a random key
def generate_key():
    return get_random_bytes(16)

# Function to encrypt data with AES
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    padded_plaintext = pad(plaintext, AES.block_size, style='pkcs7')
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(cipher.iv + ciphertext)

# Function to decrypt data with AES
def aes_decrypt(ciphertext, key):
    try:
        data = base64.b64decode(ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv=data[:16])
        decrypted_data = unpad(cipher.decrypt(data[16:]), AES.block_size, style='pkcs7')
        return decrypted_data.decode('utf-8')
    except (ValueError, KeyError, TypeError) as e:
        print(f"Decryption failed: {e}")
        return None
# Function to check if data size is a multiple of block size
def is_multiple_of_block_size(data):
    block_size = AES.block_size
    return len(data) % block_size == 0 if data is not None else False

# Function to save data to a new file
def save_to_file(data, file_path):
    with open(file_path, 'wb') as file:
        file.write(data)

# Create a random key at the beginning
encryption_key = generate_key()

# Create two separate column layouts for each section
layout1 = [
    [sg.Column(
        [
            [centered_text('AES Encryption - K0BiMaChi')],
            [sg.Input(), sg.FileBrowse()],
            [sg.Button("Encryption")],
            [sg.Text("KEY"), sg.Canvas(background_color='lightblue', size=(300, 20), key='Encryption_key')],
            [sg.Button("Copy Key")],
            [sg.Text("Encryption Output")],
            [sg.Multiline(size=(50, 5), background_color='lightblue', key='encryption_output')],
        ],
        element_justification="center",
    )]
]

layout2 = [
    [sg.Column(
        [
            [centered_text('AES Decryption - K0BiMaChi')],
            [sg.Input(), sg.FileBrowse()],
            [sg.Text("KEY"), sg.Input(key='Decryption_key')],
            [sg.Button("Decryption")],
            [sg.Text("Decryption Output")],
            [sg.Multiline(size=(50, 5), background_color='lightblue', key='decryption_output')],
        ],
        element_justification="center",
    )]
]

# Add an empty row with a border between layout1 and layout2
separator = [[sg.Canvas(background_color='lightblue', size=(900, 2))]]

# Combine layout1, separator, and layout2
final_layout = layout1 + separator + layout2

# Create the window
window = sg.Window('AES Encryption/Decryption - K0BiMaChi', final_layout)

while True:
    event, values = window.read()

    # Handle events
    if event == sg.WIN_CLOSED or event == 'Cancel':
        break
    elif event == 'Encryption':
        file_path = values[0]

        if file_path:
            # Update the canvas to display the key
            key_text = f"{encryption_key.hex()}"
            window['Encryption_key'].TKCanvas.create_text(150, 10, text=key_text, fill='black', font=('prompt', 10, 'bold'))

            # Read the file content
            with open(file_path, 'rb') as file:
                plaintext = file.read()

            # Encrypt the file content
            encrypted_data = aes_encrypt(plaintext, encryption_key)
            print(f"Is encrypted data a multiple of block size? {is_multiple_of_block_size(encrypted_data)}")
            # Update the Multiline element to display the encrypted data
            window['encryption_output'].update(f"{encrypted_data.decode('utf-8')}")

            # Save the encrypted data to a new file
            new_file_path = file_path + '.encrypted'
            save_to_file(encrypted_data, new_file_path)

            # Debug
            print(f"Key: {encryption_key.hex()}")
            print(f"Encrypted Data: {encrypted_data}")
            print(f"Is encrypted data a multiple of block size? {is_multiple_of_block_size(encrypted_data)}")
            print(f"Encrypted Data saved to: {new_file_path}")


    elif event == 'Copy Key':
        key_text = window['Encryption_key'].TKCanvas.itemcget(window['Encryption_key'].TKCanvas.find_all()[0], 'text')
        root = sg.tk.Tk()  # Use sg.tk.Tk() to access the Tkinter root
        root.clipboard_clear()
        root.clipboard_append(key_text)
        root.update()
        root.destroy()


window.close()