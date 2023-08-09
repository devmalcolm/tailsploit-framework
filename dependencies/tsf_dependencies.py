import os
from dependencies.hbfmemory import FrameworkDependenciesFiles

class Dependencies:
    def __init__(self):
        self.DELETED_DATA = []
        self.FRAMEWORK_PATH = "."

    def CheckDependencies(self):
        for dependecieshbfmemory in FrameworkDependenciesFiles:
            MemoryPath = os.path.join(self.FRAMEWORK_PATH, dependecieshbfmemory)
            if os.path.sep == "/":  # On macOS and Linux, the separator is "/"
                file_path = MemoryPath
            else:  # On Windows, the separator is "\"
                file_path = MemoryPath.replace("/", os.path.sep)

            if not os.path.exists(file_path):
                self.DELETED_DATA.append(file_path)

        return self.DELETED_DATA

    def InitiateDependencies(self):
        self.CheckDependencies()
        if len(self.DELETED_DATA) == 0:
            return True
        else:
            print("[*] Error while initializing Heartbeat, missing or corrupted file, please reinstall the framework.")
            for MissingDependencies in self.DELETED_DATA:
                print(MissingDependencies)
            return False
