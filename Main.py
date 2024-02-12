import PySimpleGUI as sg

# Function to create a centered text element
def centered_text(text, size=(32, 1), font=('prompt 32 bold')):
    return sg.Text(text, size=size, font=font, justification='center')

# Create two separate column layouts for each section
layout1 = [
    [sg.Column(
        [
            [centered_text('AES Encryption - K0BiMaChi')],
            [sg.Input(), sg.FileBrowse()],
            [sg.Button("Encryption")],
            [sg.Text('KEY'), sg.InputText(background_color="lightblue")],  # Add background color
            [sg.Text('OUTPUT'), sg.InputText(background_color="lightblue")],  # Add background color

        ],
        element_justification="center",
    )]
]

layout2 = [
    [sg.Column(
        [
            [centered_text('AES Decryption - K0BiMaChi')],
            [sg.Input(), sg.FileBrowse()],
            [sg.Text('KEY'), sg.InputText(background_color="lightblue")],
            [sg.Button("Decryption")],
            [sg.Text('OUTPUT'), sg.InputText(background_color="lightblue")],  # Add background color
        ],
        element_justification="center",
    )]
]

# Add an empty row with a border between layout1 and layout2
separator = [[sg.Text('', size=(100), justification='center', relief=sg.RELIEF_SUNKEN, text_color='black')]]

# Combine layout1, separator, and layout2
final_layout = layout1 + separator + layout2

# Create the window
window = sg.Window('AES Encryption/Decryption - K0BiMaChi', final_layout)

while True:
    event, values = window.read()

    # Handle events (you'll need to add your own event handling logic here)
    if event == sg.WIN_CLOSED or event == 'Cancel':
        break

window.close()
