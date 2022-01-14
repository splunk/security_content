
import yaml


class YmlWriter:

    @staticmethod
    def writeYmlFile(file_path : str, obj : dict) -> None:

        with open(file_path, 'w') as outfile:
            yaml.dump(obj, outfile, default_flow_style=False, sort_keys=False)