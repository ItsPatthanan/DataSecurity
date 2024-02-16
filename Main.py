import PySimpleGUI as sg
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.Random import get_random_bytes

# Function to create a centered text element
def centered_text(text, size=(32, 1), font=('prompt 32 bold')):
    return sg.Text(text, size=size, font=font, justification='center')


def generate_aes_key():
    return get_random_bytes(32)  # 256 bits

def encrypt_file(input_file, key):
    iv = get_random_bytes(16)  # Generate a random IV for each encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as file:
        plaintext = file.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv


def decrypt_file(input_file, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    with open(input_file, 'rb') as file:
        ciphertext = file.read()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(plaintext) + unpadder.finalize()

    return unpadded_data


# Create two separate column layouts for each section
layout1 = [
    [sg.Column(
        [
            [centered_text('AES Encryption - K0BiMaChi')],
            [sg.Input(), sg.FileBrowse(key='encryption_input')],
            [sg.Button("Encryption")],
            [sg.Text("KEY"), sg.Input(size=(65, 1), key='Encryption_key', readonly=True), sg.Button("Copy Key")],
            [sg.Text("Encryption Output"),sg.Input(readonly=True,size=(50, 1), background_color='lightblue', key='encryption_output')],

        ],
        element_justification="center",
    )]
]

layout2 = [
    [sg.Column(
        [
            [centered_text('AES Decryption - K0BiMaChi')],
            [sg.Input(), sg.FileBrowse(key='decryption_input')],
            [sg.Text("KEY"),sg.Input(key='Decryption_key', readonly=True,size=(65, 1)), sg.Button("Paste key")],
            [sg.Button("Decryption")],
            [sg.Text("Decryption Output"),sg.Input(readonly=True,size=(50, 1), background_color='lightblue', key='decryption_output')],
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

key_to_copy = b''  # Variable to store the generated key

while True:
    event, values = window.read()

    # Handle events
    if event == sg.WIN_CLOSED or event == 'Cancel':
        break
    elif event == 'Encryption':
        key = generate_aes_key()
        window['Encryption_key'].update(value=key.hex())
        input_file = values['encryption_input']
        ciphertext, iv = encrypt_file(input_file, key)
        window['encryption_output'].update(value='File encrypted successfully.')
        encrypted_file = input_file + '_encrypted.txt'
        with open(encrypted_file, 'wb') as file:
            file.write(iv)  # เขียน IV ลงในไฟล์
            file.write(ciphertext)
        window['encryption_output'].update(value=f'{encrypted_file}')

    elif event == 'Copy Key':
        key_to_copy = key.hex()

    elif event == 'Decryption':

        input_file = values['decryption_input']

        key = bytes.fromhex(values['Decryption_key'])

        with open(input_file, 'rb') as file:

            iv = file.read(16)  # Read the IV from the file

            decrypted_data = decrypt_file(input_file, key, iv)

        window['decryption_output'].update(value=decrypted_data)

        decrypted_filename = input_file.rsplit('.', 1)[0]  # Remove the last extension

        decrypted_filename = f'{decrypted_filename}_decrypted.txt'

        with open(decrypted_filename, 'wb') as file:

            file.write(decrypted_data)

        window['decryption_output'].update(value=f'{decrypted_filename}')

    elif event == 'Paste key':
        window['Decryption_key'].update(value=key_to_copy)

window.close()
