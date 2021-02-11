#!/bin/python
from os import path, walk
import argparse
import yaml
REPO_PATH = '/home/jhernandez/splunk/security_content/detections'

def pretty_yaml_detections():

def pretty_yaml(REPO_PATH, VERBOSE, objects):

    manifest_files = []
    types = ["endpoint", "application", "cloud", "deprecated", "experimental", "network", "web"]
    for t in types:
        for root, dirs, files in walk(REPO_PATH + "/" + t):
    #for root, dirs, files in walk(REPO_PATH + "/"):
            for file in files:
                if file.endswith(".yml"):
                    manifest_files.append((path.join(root, file)))
    for manifest_file in manifest_files:
        pretty_yaml = dict()
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
        pretty_yaml['description'] = object['description']
        if 'how_to_implement' in object:
            pretty_yaml['how_to_implement'] = object['how_to_implement']
        else:
            pretty_yaml['how_to_implement'] = ''
        pretty_yaml['type'] = object['type']
        pretty_yaml['search'] = object['search']
        pretty_yaml['author'] = object['author']
        if 'references' in object:
            pretty_yaml['references'] = object['references']
        else:
            pretty_yaml['references'] = []
        pretty_yaml['known_false_positives'] = object['known_false_positives']
        pretty_yaml['tags'] = object['tags']


        #with open(manifest_file, 'w') as file:
        #    documents = yaml.dump(object, file, default_flow_style=False, sort_keys=False)
        print(yaml.dump(pretty_yaml,default_flow_style=False, sort_keys=False))

def main(args):

    parser = argparse.ArgumentParser(description="keeps yamls in security_content sorted and pretty printed with custom sort keys")
    parser.add_argument("-p", "--path", required=True, help="path to security_content repo")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    
    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    VERBOSE = args.verbose

    pretty_yaml_objects = ['macros','lookups','stories','detections','baselines','response_tasks','responses','deployments']
    for pretty_yaml_object in pretty_yaml_objects:
        pretty_yaml(REPO_PATH, VERBOSE, pretty_yaml_object)

if __name__ == "__main__":
    main(sys.argv[1:])

