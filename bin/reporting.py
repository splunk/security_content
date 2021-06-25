#!/usr/bin/python

import glob
import yaml
import argparse
import os
from os import path
import sys
import datetime
from jinja2 import Environment, FileSystemLoader


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
    print("generated reporting information for our detections")

    # process all detections
    REPO_PATH = os.path.join(os.path.dirname(__file__), '../')
    detections = []
    detections = load_objects("detections/application/*.yml", REPO_PATH)
    detections.extend(load_objects("detections/cloud/*.yml", REPO_PATH))
    detections.extend(load_objects("detections/endpoint/*.yml", REPO_PATH))
    detections.extend(load_objects("detections/network/*.yml", REPO_PATH))
    detections.extend(load_objects("detections/web/*.yml", REPO_PATH))

    detections_all = detections.copy()

    #lets exclude all deprecated detections from our reporting and experimental
    # detections_all.extend(load_objects("detections/deprecated/*.yml", REPO_PATH))
    # detections_all.extend(load_objects("detections/experimental/*/*.yml", REPO_PATH))
    count_detections_all = len(detections_all)
    print("detection count: {}".format(count_detections_all))

    tests = load_objects("tests/*/*.yml", REPO_PATH)
    print("test count: {}".format(len(tests)))

    counter_tests=0
    counter_detection=0

    for detection in detections:
        counter_detection=counter_detection+1

    for test in tests:
        counter_tests=counter_tests+1

    detection_coverage = "{:.0%}".format(counter_detection/counter_tests)

    print("detection_coverage {}".format(detection_coverage))

    TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'jinja2_templates')
    OUTPUT_PATH = os.path.join(os.path.dirname(__file__), 'reporting')
    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH), trim_blocks=True)
    template = j2_env.get_template('detection_coverage.j2')
    output_path = path.join(OUTPUT_PATH, 'detection_coverage.svg')
    output = template.render(detection_coverage=detection_coverage)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    print("writting detection coverage report: {}".format(output_path))

    template = j2_env.get_template('detection_count.j2')
    output_path = path.join(OUTPUT_PATH, 'detection_count.svg')
    output = template.render(detection_count=count_detections_all)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    print("writting detection count report: {}".format(output_path))


if __name__ == "__main__":
    main(sys.argv[1:])
