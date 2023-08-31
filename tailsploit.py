#!/usr/bin/env python3

try:
    import os
    from colorama import Back, Style, Fore
    import sys
    from pyspin.spin import Box1, Spinner
    import time
    from dependencies.tsf_modules import ModulesImported
    from dependencies.tsf_dependencies import Dependencies

except ImportError as MissingModule:
    print(f"[*] Error while initializing Heartbeat, missing module : {MissingModule}")

class HeartBeat:
    def __init__(self):
        pass

    def HeartbeatInitialization(self):
        if ModulesImported():
            x = Dependencies()
            if x.InitiateDependencies():
                pass
            else:
                sys.exit(1)
        else:
            sys.exit(1)        
        spin = Spinner(Box1)
        print("")
        for i in range(100):
            print(u"\r{0} Initializing {1}Heartbeat{2} Framework...".format(spin.next(), Fore.RED, Style.RESET_ALL), end="")
            sys.stdout.flush()
            time.sleep(0.1)
        
        heartbeat_banner = f"""


        ┓┏  ┏┓  ┏┓  ┳┓  ┏┳┓  ┳┓  ┏┓  ┏┓  ┏┳┓
        ┣┫  ┣   ┣┫  ┣┫   ┃   ┣┫  ┣   ┣┫   ┃ 
        ┛┗  ┗┛  ┛┗  ┛┗   ┻   ┻┛  ┗┛  ┛┗   ┻ 

                  github/{Fore.RED}devmalcolm{Style.RESET_ALL}
                    {Fore.YELLOW}(v.0.2a-dev){Style.RESET_ALL}

"""     
        os.system("cls")
        print(heartbeat_banner)
        while True:
            HeartbeatShell = input(f"\x1B[4m{Fore.RED}heartbeat\x1B[0m{Style.RESET_ALL}\x1B[4m@shell\x1B[0m > ") 
            print("")
            if HeartbeatShell == "":
                continue



x = HeartBeat()
x.HeartbeatInitialization()

