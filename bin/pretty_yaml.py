#!/bin/python
from os import path, walk
import sys
import argparse
import yaml
import re

def parse_data_models_from_search(search):
    match = re.search(r'from\sdatamodel\s?=\s?([^\s.]*)', search)
    if match is not None:
        return match.group(1)
    return False

def pretty_yaml_detections(REPO_PATH, VERBOSE, content_part):
    manifest_files = []
    types = ["endpoint", "application", "cloud", "deprecated", "experimental", "network", "web"]
    for t in types:
        for root, dirs, files in walk(REPO_PATH + "/" + content_part + '/' + t):
            for file in files:
                if file.endswith(".yml"):
                    manifest_files.append((path.join(root, file)))

    for manifest_file in manifest_files:
        pretty_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue

        pretty_yaml['name'] = object['name']
        pretty_yaml['id'] = object['id']
        pretty_yaml['version'] = object['version']
        pretty_yaml['date'] = object['date']
        pretty_yaml['author'] = object['author']
        pretty_yaml['type'] = object['type']
        pretty_yaml['datamodel'] = object['datamodel']
        pretty_yaml['description'] = object['description']
        pretty_yaml['search'] = object['search']
        if 'how_to_implement' in object:
            pretty_yaml['how_to_implement'] = object['how_to_implement']
        else:
            pretty_yaml['how_to_implement'] = ''
        pretty_yaml['known_false_positives'] = object['known_false_positives']
        if 'references' in object:
            pretty_yaml['references'] = object['references']
        else:
            pretty_yaml['references'] = []
        pretty_yaml['tags'] = object['tags']


        with open(manifest_file, 'w') as file:
            documents = yaml.dump(pretty_yaml, file, sort_keys=False)

    return manifest_files

def pretty_yaml_baselines(REPO_PATH, VERBOSE, content_part):
    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + "/" + content_part + '/'):
        for file in files:
            if file.endswith(".yml"):
                manifest_files.append((path.join(root, file)))

    for manifest_file in manifest_files:
        pretty_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue

        pretty_yaml['name'] = object['name']
        pretty_yaml['id'] = object['id']
        pretty_yaml['version'] = object['version']
        pretty_yaml['date'] = object['date']
        pretty_yaml['author'] = object['author']
        pretty_yaml['type'] = object['type']
        pretty_yaml['datamodel'] = object['datamodel']
        pretty_yaml['description'] = object['description']
        pretty_yaml['search'] = object['search']
        if 'how_to_implement' in object:
            pretty_yaml['how_to_implement'] = object['how_to_implement']
        else:
            pretty_yaml['how_to_implement'] = ''
        if 'references' in object:
            pretty_yaml['references'] = object['references']
        else:
            pretty_yaml['references'] = []
        pretty_yaml['tags'] = object['tags']

        with open(manifest_file, 'w') as file:
            documents = yaml.dump(pretty_yaml, file, sort_keys=False)

    return manifest_files

def pretty_yaml_baselines(REPO_PATH, VERBOSE, content_part):
    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + "/" + content_part + '/'):
        for file in files:
            if file.endswith(".yml"):
                manifest_files.append((path.join(root, file)))

    for manifest_file in manifest_files:
        pretty_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue

        pretty_yaml['name'] = object['name']
        pretty_yaml['id'] = object['id']
        pretty_yaml['version'] = object['version']
        pretty_yaml['date'] = object['date']
        pretty_yaml['author'] = object['author']
        pretty_yaml['type'] = object['type']
        pretty_yaml['datamodel'] = object['datamodel']
        pretty_yaml['description'] = object['description']
        pretty_yaml['search'] = object['search']
        if 'how_to_implement' in object:
            pretty_yaml['how_to_implement'] = object['how_to_implement']
        else:
            pretty_yaml['how_to_implement'] = ''
        if 'references' in object:
            pretty_yaml['references'] = object['references']
        else:
            pretty_yaml['references'] = []
        pretty_yaml['tags'] = object['tags']

        with open(manifest_file, 'w') as file:
            documents = yaml.dump(pretty_yaml, file, sort_keys=False)

    return manifest_files

def pretty_yaml_deployments(REPO_PATH, VERBOSE, content_part):
    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + "/" + content_part + '/'):
        for file in files:
            if file.endswith(".yml"):
                manifest_files.append((path.join(root, file)))

    for manifest_file in manifest_files:
        pretty_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue

        pretty_yaml['name'] = object['name']
        pretty_yaml['id'] = object['id']
        pretty_yaml['date'] = object['date']
        pretty_yaml['author'] = object['author']
        pretty_yaml['description'] = object['description']
        pretty_yaml['scheduling'] = object['scheduling']
        if 'alert_action' in object:
            pretty_yaml['alert_action'] = object['alert_action']
        pretty_yaml['tags'] = object['tags']

        with open(manifest_file, 'w') as file:
            documents = yaml.dump(pretty_yaml, file, sort_keys=False)

    return manifest_files

def pretty_yaml_stories(REPO_PATH, VERBOSE, content_part):
    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + "/" + content_part + '/'):
        for file in files:
            if file.endswith(".yml"):
                manifest_files.append((path.join(root, file)))

    for manifest_file in manifest_files:
        pretty_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue

        pretty_yaml['name'] = object['name']
        pretty_yaml['id'] = object['id']
        pretty_yaml['version'] = object['version']
        pretty_yaml['date'] = object['date']
        pretty_yaml['author'] = object['author']
        pretty_yaml['type'] = object['type']
        pretty_yaml['description'] = object['description']
        pretty_yaml['narrative'] = object['narrative']
        if 'references' in object:
            pretty_yaml['references'] = object['references']
        else:
            pretty_yaml['references'] = []
        pretty_yaml['tags'] = object['tags']

        with open(manifest_file, 'w') as file:
            documents = yaml.dump(pretty_yaml, file, sort_keys=False)

    return manifest_files

def pretty_yaml(REPO_PATH, VERBOSE, content_part):
    #for root, dirs, files in walk(REPO_PATH + "/"):
    manifest_files = []
    if content_part == 'detections':
        manifest_files = pretty_yaml_detections(REPO_PATH, VERBOSE, content_part)
    elif content_part == 'baselines':
        manifest_files = pretty_yaml_baselines(REPO_PATH, VERBOSE, content_part)
    elif content_part == 'deployments':
        manifest_files = pretty_yaml_deployments(REPO_PATH, VERBOSE, content_part)
    elif content_part == 'stories':
        manifest_files = pretty_yaml_stories(REPO_PATH, VERBOSE, content_part)
    return len(manifest_files)

def main(args):

    parser = argparse.ArgumentParser(description="keeps yamls in security_content sorted and pretty printed with custom sort keys, \
            meant to run quitely for CI, use -v flag to make it bark")

    parser.add_argument("-p", "--path", required=True, help="path to security_content repo")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    VERBOSE = args.verbose
    output = []
    pretty_yaml_objects = ['macros','lookups','stories','detections','baselines','response_tasks','responses','deployments']
    for pretty_yaml_object in pretty_yaml_objects:
        touch_count = pretty_yaml(REPO_PATH, VERBOSE, pretty_yaml_object)
        if VERBOSE:
            output.append("made {0} {1} pretty".format(touch_count, pretty_yaml_object))

    for o in output:
        print(o)

    print("finished successfully!")


if __name__ == "__main__":
    main(sys.argv[1:])
