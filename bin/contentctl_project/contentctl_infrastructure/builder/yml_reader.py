from typing import Dict

import yaml
import sys

class YmlReader():

    @staticmethod
    def load_file(file_path: str) -> Dict:
        try:
            file_handler = open(file_path, 'r', encoding="utf-8")
            try:
                yml_obj = list(yaml.safe_load_all(file_handler))[0]
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit(1)

        except OSError as exc:
            print(exc)
            sys.exit(1)

        yml_obj['file_path'] = file_path

        if 'deprecated' in file_path:
            yml_obj['deprecated'] = True
        else:
            yml_obj['deprecated'] = False

        if 'experimental' in file_path:
            yml_obj['experimental'] = True
        else:
            yml_obj['experimental'] = False

        return yml_obj
