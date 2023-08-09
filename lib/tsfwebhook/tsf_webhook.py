import requests
import datetime
import json
import sys
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
json_file_path = os.path.join(script_dir, "tailsploit-webhook-config.json")

with open(json_file_path, "r") as file:
    json_data = json.load(file)

TAILSPLOIT_WEBHOOK_COMMAND_LOG = json_data["TAILSPLOIT_WEBHOOK_COMMAND_LOG"]
TAILSPLOIT_WEBHOOK_CONNECTION_LOG = json_data["TAILSPLOIT_WEBHOOK_CONNECTION_LOG"]


def TailsploitIncomingConnectionRegularClient(BotAddr):
    current_time = datetime.datetime.utcnow().isoformat()

    embed = {
            "author": {
                "name": "Tailsploit Framework | Incoming Client Connection",
            },
            "description": "New Incoming Connection (Infected Client)",
            "color": 0xFFFFFF,
            "footer": {
                "text": "Tailsploit Framework"
            },
            "thumbnail": {
            "url": "https://gcdnb.pbrd.co/images/MqM0YKM6AwUu.png?o=1"
            },
            "fields": [
                {
                "name": "Bot IP/PORT",
                "value": f"{BotAddr[0]}:{BotAddr[1]}",
                "inline": True
                },
            ],
            "timestamp": current_time 
        }
    payload = {
        "embeds": [embed]
        }
    try:
        response = requests.post(TAILSPLOIT_WEBHOOK_CONNECTION_LOG, json=payload)
        response.raise_for_status()
        #print("Webhook sent successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send webhook: {e}")


def TailsploitDiscordCommand(AdminUsername, ContentCommand):
        current_time = datetime.datetime.utcnow().isoformat()

        embed = {
            "author": {
                "name": "Tailsploit Framework | Botnet Command",
            },
            "description": ContentCommand,
            "color": 0xFFFFFF,
            "footer": {
                "text": "Tailsploit Framework"
            },
            "thumbnail": {
            "url": "https://gcdnb.pbrd.co/images/MqM0YKM6AwUu.png?o=1"
            },
            "fields": [
                {
                    "name": "Admin Username",
                    "value": AdminUsername,
                    "inline": True
                },
                {
                "name": "Admin IP/PORT",
                "value": "127.0.0.1:5231",
                "inline": True
                },
            ],
            "timestamp": current_time 
        }

        payload = {
            "embeds": [embed]
        }

        try:
            response = requests.post(TAILSPLOIT_WEBHOOK_COMMAND_LOG, json=payload)
            response.raise_for_status()
            #print("Webhook sent successfully.")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send webhook: {e}")


def TailsploitIncomingConnectionAdminClient(AdminAddr):
        current_time = datetime.datetime.utcnow().isoformat()

        embed = {
            "author": {
                "name": "Tailsploit Framework | Admin Incoming Connection",
            },
            "description": "New Incoming Admin Connection",
            "color": 0xFFCB4B,
            "footer": {
                "text": "Tailsploit Framework"
            },
            "thumbnail": {
            "url": "https://gcdnb.pbrd.co/images/MqM0YKM6AwUu.png?o=1"
            },
            "fields": [
                {
                "name": "Admin IP/PORT",
                "value": f"{AdminAddr[0]}:{AdminAddr[1]}",
                "inline": True
                },
            ],
            "timestamp": current_time 
        }

        payload = {
            "embeds": [embed]
        }

        try:
            response = requests.post(TAILSPLOIT_WEBHOOK_CONNECTION_LOG, json=payload)
            response.raise_for_status()
            #print("Webhook sent successfully.")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send webhook: {e}")


def TailsploitIncomingConnectionAdminClientAuthorized(AdminAddr):
        current_time = datetime.datetime.utcnow().isoformat()

        embed = {
            "author": {
                "name": "Tailsploit Framework | Admin Established Connection",
            },
            "description": "Admin connection established",
            "color": 0x5FFF3F,
            "footer": {
                "text": "Tailsploit Framework"
            },
            "thumbnail": {
            "url": "https://gcdnb.pbrd.co/images/MqM0YKM6AwUu.png?o=1"
            },
            "fields": [
                {
                "name": "Admin IP/PORT",
                "value": f"{AdminAddr[0]}:{AdminAddr[1]}",
                "inline": True
                },
            ],
            "timestamp": current_time 
        }

        payload = {
            "embeds": [embed]
        }

        try:
            response = requests.post(TAILSPLOIT_WEBHOOK_CONNECTION_LOG, json=payload)
            response.raise_for_status()
            #print("Webhook sent successfully.")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send webhook: {e}")

def TailsploitIncomingConnectionAdminClientRejectedTokenAlreadyInUse(AdminAddr):
        current_time = datetime.datetime.utcnow().isoformat()

        embed = {
            "author": {
                "name": "Tailsploit Framework | Admin Rejected Connection",
            },
            "description": "Admin Rejected Connection (Provided token is already in use)",
            "color": 0xFF5C5C,
            "footer": {
                "text": "Tailsploit Framework"
            },
            "thumbnail": {
            "url": "https://gcdnb.pbrd.co/images/MqM0YKM6AwUu.png?o=1"
            },
            "fields": [
                {
                "name": "Admin IP/PORT",
                "value": f"{AdminAddr[0]}:{AdminAddr[1]}",
                "inline": True
                },
            ],
            "timestamp": current_time 
        }

        payload = {
            "embeds": [embed]
        }

        try:
            response = requests.post(TAILSPLOIT_WEBHOOK_CONNECTION_LOG, json=payload)
            response.raise_for_status()
            #print("Webhook sent successfully.")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send webhook: {e}")


def TailsploitIncomingConnectionAdminClientRejectedTokenNotValid(AdminAddr):
        current_time = datetime.datetime.utcnow().isoformat()

        embed = {
            "author": {
                "name": "Tailsploit Framework | Admin Rejected Connection",
            },
            "description": "Admin Rejected Connection (Provided token is not valid)",
            "color": 0xFF5C5C,
            "footer": {
                "text": "Tailsploit Framework"
            },
            "thumbnail": {
            "url": "https://gcdnb.pbrd.co/images/MqM0YKM6AwUu.png?o=1"
            },
            "fields": [
                {
                "name": "Admin IP/PORT",
                "value": f"{AdminAddr[0]}:{AdminAddr[1]}",
                "inline": True
                },
            ],
            "timestamp": current_time 
        }

        payload = {
            "embeds": [embed]
        }

        try:
            response = requests.post(TAILSPLOIT_WEBHOOK_CONNECTION_LOG, json=payload)
            response.raise_for_status()
            #print("Webhook sent successfully.")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send webhook: {e}")


def TailsploitIncomingConnectionAdminClientRejectedTokenRevoked(AdminAddr):
        current_time = datetime.datetime.utcnow().isoformat()

        embed = {
            "author": {
                "name": "Tailsploit Framework | Admin Rejected Connection",
            },
            "description": "Admin Rejected Connection (Provided token has been revoked)",
            "color": 0xFF5C5C,
            "footer": {
                "text": "Tailsploit Framework"
            },
            "thumbnail": {
            "url": "https://gcdnb.pbrd.co/images/MqM0YKM6AwUu.png?o=1"
            },
            "fields": [
                {
                "name": "Admin IP/PORT",
                "value": f"{AdminAddr[0]}:{AdminAddr[1]}",
                "inline": True
                },
            ],
            "timestamp": current_time 
        }

        payload = {
            "embeds": [embed]
        }

        try:
            response = requests.post(TAILSPLOIT_WEBHOOK_CONNECTION_LOG, json=payload)
            response.raise_for_status()
            #print("Webhook sent successfully.")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send webhook: {e}")
            

def TailsploitWebRequestFirstIndex():
        current_time = datetime.datetime.utcnow().isoformat()

        embed = {
            "author": {
                "name": "Tailsploit Framework | Checking Webhook Status",
            },
            "description": "Tailsploit Webhook Working.",
            "color": 0xFFFFFF,
            "footer": {
                "text": "Tailsploit Framework"
            },
            "thumbnail": {
            "url": "https://gcdnb.pbrd.co/images/MqM0YKM6AwUu.png?o=1"
            },
            "fields": [
                {
                "name": "xxxx xx/xxxx",
                "value": f"xxxx:xxxx",
                "inline": True
                },
            ],
            "timestamp": current_time 
        }

        payload = {
            "embeds": [embed]
        }

        try:
            response = requests.post(TAILSPLOIT_WEBHOOK_CONNECTION_LOG, json=payload)
            response.raise_for_status()
            return "--FLAG_WEBHOOK_FIRST_SUCESS"
        except requests.exceptions.RequestException as e:
            return "--FLAG_WEBHOOK_FIRST_ERROR"

def TailsploitWebRequestSecondIndex():
        current_time = datetime.datetime.utcnow().isoformat()

        embed = {
            "author": {
                "name": "Tailsploit Framework | Checking Webhook Status",
            },
            "description": "Tailsploit Webhook Working.",
            "color": 0xFFFFFF,
            "footer": {
                "text": "Tailsploit Framework"
            },
            "thumbnail": {
            "url": "https://gcdnb.pbrd.co/images/MqM0YKM6AwUu.png?o=1"
            },
            "fields": [
                {
                "name": "xxxx xx/xxxx",
                "value": f"xxxx:xxxx",
                "inline": True
                },
            ],
            "timestamp": current_time 
        }

        payload = {
            "embeds": [embed]
        }

        try:
            response = requests.post(TAILSPLOIT_WEBHOOK_COMMAND_LOG, json=payload)
            response.raise_for_status()
            return "--FLAG_WEBHOOK_SECOND_SUCESS"
        except requests.exceptions.RequestException as e:
            return "--FLAG_WEBHOOK_SECOND_ERROR"












