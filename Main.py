import PySimpleGUI as sg
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64

# Function to create a centered text element
def centered_text(text, size=(32, 1), font=('prompt 32 bold')):
    return sg.Text(text, size=size, font=font, justification='center')

# Function to generate a random key
def generate_key():
    return get_random_bytes(16)

# Function to encrypt data with AES
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext)

# Function to save data to a new file
def save_to_file(data, file_path):
    with open(file_path, 'wb') as file:
        file.write(data)

# Create two separate column layouts for each section
layout1 = [
    [sg.Column(
        [
            [centered_text('AES Encryption - K0BiMaChi')],
            [sg.Input(), sg.FileBrowse()],
            [sg.Button("Encryption")],
            [sg.Text("KEY"), sg.Canvas(background_color='lightblue', size=(300, 20), key='key_canvas')],
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
            [sg.Button("Decryption")]
        ],
        element_justification="center",
    )]
]

# Add an empty row with a border between layout1 and layout2
separator = [[sg.Canvas(background_color='lightblue', size=(900, 1))]]

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
            # Generate a random key
            key = generate_key()

            # Update the canvas to display the key
            window['key_canvas'].TKCanvas.create_text(150, 10, text=f"{key.hex()}", fill='black', font=('prompt', 10, 'bold'))

            # Read the file content
            with open(file_path, 'rb') as file:
                plaintext = file.read()

            # Encrypt the file content
            encrypted_data = aes_encrypt(plaintext, key)

            # Update the Multiline element to display the encrypted data
            window['encryption_output'].update(f"{encrypted_data.decode('utf-8')}")

            # Save the encrypted data to a new file
            new_file_path = file_path + '.encrypted'
            save_to_file(encrypted_data, new_file_path)
            
            # Debug
            print(f"Key: {key.hex()}")
            print(f"Encrypted Data: {encrypted_data}")
            print(f"Encrypted Data saved to: {new_file_path}")

window.close()
