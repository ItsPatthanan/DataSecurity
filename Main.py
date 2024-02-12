import PySimpleGUI as sg
layout = [
    [sg.Text('AES Encryption - K0BiMaChi',size=(32,1),font=('prompt 32 bold'))],
    [sg.Input(), sg.FileBrowse()],
    [sg.OK(), sg.Cancel()],
]
window = sg.Window('Example1', layout)
window.close()