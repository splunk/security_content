import json


class JsonWriter():

    @staticmethod
    def writeJsonObject(file_path : str, obj) -> None:

        with open(file_path, 'w') as outfile:
            json.dump(obj, outfile, ensure_ascii=False)