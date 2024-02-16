import PySimpleGUI as sg
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Function to create a centered text element
def centered_text(text, size=(32, 1), font=('prompt 32 bold')):
    return sg.Text(text, size=size, font=font, justification='center')


def generate_aes_key():
    return get_random_bytes(32)  # 256 bits

def encrypt_file(input_file, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(input_file, 'rb') as file:
        plaintext = file.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, cipher.iv

def decrypt_file(input_file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(input_file, 'rb') as file:
        ciphertext = file.read()
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data

# Create two separate column layouts for each section
layout1 = [
    [sg.Column(
        [
            [centered_text('AES Encryption - K0BiMaChi')],
            [sg.Input(), sg.FileBrowse(key='encryption_input')],
            [sg.Button("Encryption"),sg.Button("Clear Encryption")],
            [sg.Text("KEY")],
            [sg.Canvas(background_color='lightblue', size=(400, 20), key='Encryption_key'), sg.Button("Copy Key")],
            [sg.Text("Encryption Output")],
            [sg.Multiline(size=(50, 2), background_color='lightblue', key='encryption_output')],

        ],
        element_justification="center",
    )]
]

layout2 = [
    [sg.Column(
        [
            [centered_text('AES Decryption - K0BiMaChi')],
            [sg.Input(), sg.FileBrowse(key='decryption_input')],
            [sg.Text("KEY")],
            [sg.Input(key='Decryption_key'), sg.Button("Paste key")],
            [sg.Button("Decryption"),sg.Button("Clear Decryption")],
            [sg.Text("Decryption Output")],
            [sg.Multiline(size=(50, 2), background_color='lightblue', key='decryption_output')],
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
        window['Encryption_key'].TKCanvas.create_text(150, 10, text=key.hex(), font=('Helvetica', 10))
        input_file = values['encryption_input']
        ciphertext, iv = encrypt_file(input_file, key)
        window['encryption_output'].update(value='File encrypted successfully.')
        encrypted_file = input_file + '.enc'
        with open(encrypted_file, 'wb') as file:
            file.write(iv + ciphertext)
        window['encryption_output'].update(value=f'Encrypted file saved as: {encrypted_file}')

    elif event == 'Clear Encryption':
        window['encryption_input'].update()
        window['Encryption_key'].TKCanvas.delete("all")
        window['encryption_output'].update(value='')

    elif event == 'Copy Key':
        key_to_copy = key
    elif event == 'Decryption':
        input_file = values['decryption_input']
        key = bytes.fromhex(values['Decryption_key'])
        with open(input_file, 'rb') as file:
            iv = file.read(16)  # Read the IV from the file
            decrypted_data = decrypt_file(input_file, key, iv)
        decrypted_data_str = decrypted_data.decode('utf-8', errors='replace')
        window['decryption_output'].update(value=decrypted_data_str)
        # Generate a new filename for the decrypted file
        decrypted_filename = input_file.rsplit('.', 1)[0]  # Remove the last extension
        decrypted_filename = f'{decrypted_filename}.txt'
        with open(decrypted_filename, 'w', encoding='utf-8') as file:
            file.write(decrypted_data_str)
        window['decryption_output'].update(value=f'Decrypted file saved as: {decrypted_filename}')
    elif event == 'Clear Decryption':
        window['decryption_input'].update()
        window['Decryption_key'].update(value='')
        window['decryption_output'].update(value='')

    elif event == 'Paste key':
        window['Decryption_key'].update(value=key_to_copy.hex())
window.close()
