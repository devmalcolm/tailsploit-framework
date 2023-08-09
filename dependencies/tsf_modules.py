def ModulesImported():
    required_modules = [
        "os", "sys", "re", "requests", "colorama",
        "pyspin.spin", "time", "socket",
        "threading", "json", "datetime", "subprocess",
        "winreg", "ctypes", "shutil"
    ]

    for module_name in required_modules:
        try:
            __import__(module_name)
        except ImportError as MissingModule:
            print("")
            print(f"[-] Error while starting Heartbeat Framework (Missing Module): {MissingModule}")
            return False

    return True