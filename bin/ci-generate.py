#!/usr/bin/python

'''
Generates circleci jobs from the tests under /tests in the security-content repo.
'''

import glob
import yaml
import argparse
from os import path
import sys
import datetime
from jinja2 import Environment, FileSystemLoader
import re


# global variables
REPO_PATH = ''
VERBOSE = False
OUTPUT_PATH = ''

def load_objects(file_path, VERBOSE):
    files = []
    test_files = path.join(path.expanduser(REPO_PATH), file_path)
    for file in sorted(glob.glob(test_files)):
        if VERBOSE:
            print("processing test: {0}".format(file))
        files.append(load_file(file))
    return files


def load_file(file_path):
    with open(file_path, 'r') as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def generate_circleci_conf(tests, OUTPUT_PATH, VERBOSE):
    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('circleci_config.j2')
    output_path = OUTPUT_PATH + "config.yml"
    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
    output = template.render(detection_tests=tests, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="generates circleci config file from tests", epilog="""
    This generates circleci config files that includes all of our CI logic as well as a dynamically created set of detection tests.
    The detection tests are defined under the /tests folder on the security-content repository.
    The config file is saved under the .circleci/config.yml file.""")
    parser.add_argument("-p", "--path", required=False, default=".", help="path to security-content repo, defaults to: .")
    parser.add_argument("-o", "--output", required=False, default=".circleci/", help="path to the output directory of circleci config, defaults to: .circleci/")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_PATH = args.output
    VERBOSE = args.verbose
    tests = load_objects("tests/*.yml", VERBOSE)
    generate_circleci_conf(tests, OUTPUT_PATH, VERBOSE)
    if VERBOSE:
        print("{0} tests have been successfully written to {1}".format(len(tests), OUTPUT_PATH))
        print("security content circleci config generation completed..")
