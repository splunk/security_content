import os

class Utils:

    @staticmethod
    def get_all_yml_files_from_directory(path: str) -> list:
        listOfFiles = list()
        for (dirpath, dirnames, filenames) in os.walk(path):
            for file in filenames:
                if file.endswith(".yml"):
                    listOfFiles.append(os.path.join(dirpath, file))
    
        return sorted(listOfFiles)