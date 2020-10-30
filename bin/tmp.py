import os
import sys
import yaml
import glob
import re




def convert_test_content():
    test_files = glob.glob("tests/*.yml")

    for test_file in test_files:
        old_test_obj = load_file(test_file)

        for detection in old_test_obj['detections']:
            new_test_obj = {}
            new_test_obj['name'] = detection['name'] + ' Unit Test'
            new_test_obj['detections'] = [detection]
            new_test_obj['attack_data'] = old_test_obj['attack_data']

            new_file_name = new_test_obj['detections'][0]['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
            with open('tests/endpoint/' + new_file_name + '.test.yml', 'w+' ) as outfile:
    	           yaml.dump(new_test_obj, outfile, default_flow_style=False, sort_keys=False)


def load_file(file_path):
    with open(file_path, 'r') as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


if __name__ == "__main__":
    convert_test_content()
