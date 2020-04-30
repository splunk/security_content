#!/usr/bin/python

'''
Validates Manifest file under the security-content repo for correctness.
'''

import glob
import json
import jsonschema
import yaml
import sys
import argparse
from os import path


def validate_schema(REPO_PATH, type, objects):

    error = False

    schema_file = path.join(path.expanduser(REPO_PATH), 'spec/' + type + '.spec.json')

    try:
        schema = json.loads(open(schema_file, 'rb').read())
    except IOError:
        print("ERROR: reading schema file {0}".format(schema_file))

    manifest_files = path.join(path.expanduser(REPO_PATH), type + '/*.yml')

    for manifest_file in glob.glob(manifest_files):
        if verbose:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue

        try:
            jsonschema.validate(instance=object, schema=schema)
        except jsonschema.exceptions.ValidationError as json_ve:
            print("ERROR: {0} at:\n\t{1}".format(json.dumps(json_ve.message), manifest_file))
            print("\tAffected Object: {}".format(json.dumps(json_ve.instance)))
            error = True

        if type in objects:
            objects[type].append(object)
        else:
            objects[type] = [object]

    return objects, error




def validate_object(REPO_PATH, schema_path, manifest_path, verbose, lookups=None, macros=None):
    ''' Validate scheme '''

    # uuids
    uuids = []

    schema_file = path.join(path.expanduser(REPO_PATH), schema_path)

    try:
        schema = json.loads(open(schema_file, 'rb').read())
    except IOError:
        print("ERROR: reading schema file {0}".format(schema_file))

    objects = {}
    manifest_files = path.join(path.expanduser(REPO_PATH), manifest_path)

    for manifest_file in glob.glob(manifest_files):
        if verbose:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue

        try:
            jsonschema.validate(instance=object, schema=schema)
        except jsonschema.exceptions.ValidationError as json_ve:
            print("ERROR: {0} at:\n\t{1}".format(json.dumps(json_ve.message), manifest_file))
            print("\tAffected Object: {}".format(json.dumps(json_ve.instance)))
            error = True



        # validate content
        if schema_path == 'spec/lookups.spec.json':
            lookup_errors = validate_lookups_content(REPO_PATH, "lookups/%s", object, manifest_file)
        elif schema_path == 'spec/baselines.spec.json' or schema_path == 'spec/stories.spec.json' or schema_path == 'spec/detections.spec.json':
            errors, uuids = validate_standard_fields(object, uuids)


        #check for duplicate uuids


        #list errors
        for err in baselines_errors:
            print("{0} at:\n\t {1}".format(err, baselines_manifest_file))

        return error


def validate_standard_fields(object, uuids):

    errors = []

    if object['id'] == '':
        errors.append('ERROR: Blank ID')

    if object['id'] in uuids:
        errors.append('ERROR: Duplicate UUID found: %s' % object['id'])
    else:
        uuids.append(object['id'])

    if object['name'].endswith(" "):
        errors.append(
            "ERROR: name has trailing spaces: '%s'" %
            object['name'])

    try:
        object['description'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("ERROR: description not ascii")

    if 'how_to_implement' in object:
        try:
            object['how_to_implement'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: how_to_implement not ascii")

    return errors, uuids


def validate_search():
    pass


def validate_lookups_content(REPO_PATH, lookup_path, lookup, manifest_file):
    errors = []
    if 'filename' in lookup:
        lookup_csv_file = path.join(path.expanduser(REPO_PATH), lookup_path % lookup['filename'])
        if not path.isfile(lookup_csv_file):
            errors.append("ERROR: filename {} does not exist".format(lookup['filename']))

    return errors


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="validates security content manifest files", epilog="""
        Validates security manifest for correctness, adhering to spec and other common items.
        VALIDATE DOES NOT PROCESS RESPONSES SPEC for the moment.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-security content repo")
    parser.add_argument("-v", "--verbose", required=False, action='store_true', help="prints verbose output")
    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    verbose = args.verbose

    validate_objects = ['macros','lookups','stories','detections','response_tasks','responses','deployments']

    objects = {}
    schema_error = False

    for validation_object in validate_objects:
        objects, error = validate_schema(REPO_PATH, validation_object, objects)
        schema_error = schema_error or error

    print(objects)

    if schema_error:
        sys.exit("Errors found")
    else:
        print("No Errors found")
