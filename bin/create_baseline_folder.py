#!/usr/bin/python

import glob
import yaml
import os
from os import path
import sys


def load_objects(file_path, REPO_PATH):
    files = []
    manifest_files = path.join(path.expanduser(REPO_PATH), file_path)
    for file in sorted(glob.glob(manifest_files)):
        files.append(load_file(file))
    return files


def load_file(file_path):
    with open(file_path, 'r', encoding="utf-8") as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def main(args):
    print("copy baselines into it's own folder")

    # process all detections
    REPO_PATH = os.path.join(os.path.dirname(__file__), '../')
    detections = []
    detections = load_objects("detections/application/*.yml", REPO_PATH)
    detections.extend(load_objects("detections/cloud/*.yml", REPO_PATH))
    detections.extend(load_objects("detections/endpoint/*.yml", REPO_PATH))
    detections.extend(load_objects("detections/network/*.yml", REPO_PATH))
    detections.extend(load_objects("detections/web/*.yml", REPO_PATH))

    baselines = []
    os.mkdir('baselines')

    for detection in detections:
        if detection['type'] == 'Baseline':
            baseline_file_name =  detection['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
            file = open("baselines/" + baseline_file_name + ".yml", "w")
            yaml.dump(detection, file)
            file.close()


if __name__ == "__main__":
    main(sys.argv[1:])