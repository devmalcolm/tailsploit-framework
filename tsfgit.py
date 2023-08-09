import re
import requests
from colorama import Back, Style, Fore

class DependenciesGIT:
    def __init__(self):
        self.raw_content = "https://raw.githubusercontent.com/zaqoQLF/reverse-shell/main/src/reverse-shell/server.py"
        self.hbf_version = "0.0.21"

    def InitiateDependenciesGIT(self):
        try:
            __data__ = requests.get(f"{self.raw_content}")
            raw_version = str(re.findall(
                'self.current_version = "(.*)"', __data__.text)[0])
            if raw_version != self.hbf_version:
                print(f"[{Fore.BLUE}*{Style.RESET_ALL}] A newer version of {Fore.RED}Heartbeat Framework{Style.RESET_ALL} is available. ({Fore.YELLOW}{self.hbf_version}{Style.RESET_ALL} > {Fore.GREEN}{raw_version}{Style.RESET_ALL})")
                k = input("> Would you like to be redirected ? y/n ")
            else:
                return True
        except Exception:
            pass


FrameworkDependenciesGIT = DependenciesGIT()
FrameworkDependenciesGIT.InitiateDependenciesGIT()