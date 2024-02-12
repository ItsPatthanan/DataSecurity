import PySimpleGUI as sg
layout = [
    [sg.Text('AES Encryption - K0BiMaChi')],
    [sg.Input(), sg.FileBrowse()],
    [sg.OK(), sg.Cancel()]
]
window = sg.Window('Example1', layout)
event, values = window.read()
sg.Popup('User input', values[0]) #show user input
window.close()