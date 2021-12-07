import os


class Utils:

    @staticmethod
    def get_all_files_from_directory(path: str) -> list:
        print(path)
        listOfFiles = list()
        for (dirpath, dirnames, filenames) in os.walk(path):
            listOfFiles += [os.path.join(dirpath, file) for file in filenames]
        
        return listOfFiles