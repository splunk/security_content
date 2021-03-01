import sys
import yaml
import time
import os
import requests

from data_manipulation import DataManipulation


def load_file(file_path):
    with open(file_path, 'r', encoding="utf-8") as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def prepare_test(file_path):

    # read test file and return as object
    test_obj = load_file(file_path)

    # download attack data
    epoch_time = str(int(time.time()))
    folder_name = "attack_data_" + epoch_time
    os.mkdir(folder_name)

    for test in test_obj['tests']:
        for attack_data in test['attack_data']:
            url = attack_data['data']
            r = requests.get(url, allow_redirects=True)
            open(folder_name + '/' + attack_data['file_name'], 'wb').write(r.content)

            # Update timestamps before replay
            if 'update_timestamp' in attack_data:
                if attack_data['update_timestamp'] == True:
                    data_manipulation = DataManipulation()
                    data_manipulation.manipulate_timestamp(folder_name + '/' + attack_data['file_name'], self.log, attack_data['sourcetype'], attack_data['source'])

