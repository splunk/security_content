#!/usr/bin/python

'''
Validates Manifest file under the security_content repo for correctness.
'''

import glob
import json
import jsonschema
import yaml
import sys
import argparse
import datetime
import string
import re
from os import path, walk


def validate_schema(REPO_PATH, type, objects):

    error = False
    errors = []

    schema_file = path.join(path.expanduser(REPO_PATH), 'spec/' + type + '.spec.json')

    try:
        schema = json.loads(open(schema_file, 'rb').read())
    except IOError:
        print("ERROR: reading schema file {0}".format(schema_file))

    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + "/" + type):
        for file in files:
            if file.endswith(".yml"):
                manifest_files.append((path.join(root, file)))

    for manifest_file in manifest_files:
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
            errors.append("ERROR: {0} at:\n\t{1}".format(json.dumps(json_ve.message), manifest_file))
            error = True

        if type in objects:
            objects[type].append(object)
        else:
            arr = []
            arr.append(object)
            objects[type] = arr

    return objects, error, errors


def validate_objects(REPO_PATH, objects, verbose):

    # uuids
    uuids = []
    errors = []

    for lookup in objects['lookups']:
        lookup_errors = validate_lookups_content(REPO_PATH, "lookups/%s", lookup)

    objects_array = objects['stories'] + objects['detections'] + objects['baselines'] + objects['response_tasks'] + objects['responses']
    for object in objects_array:
        validation_errors, uuids = validate_standard_fields(object, uuids)
        errors = errors + validation_errors

    if verbose:
        print("validating object {0}".format(object['name']))
    for object in objects['detections']:
        if object['type'] == 'batch':
            errors = errors + validate_detection_search(object, objects['macros'])

    for object in objects['baselines']:
        errors = errors + validate_baseline_search(object, objects['macros'])

    errors = lookup_errors + errors

    return errors


def validate_standard_fields(object, uuids):

    errors = []

    if object['id'] == '':
        errors.append('ERROR: Blank ID for object: %s' % object['name'])

    if object['id'] in uuids:
        errors.append('ERROR: Duplicate UUID found for object: %s' % object['name'])
    else:
        uuids.append(object['id'])

    # if object['name'].endswith(" "):
    #     errors.append(
    #         "ERROR: name has trailing spaces: '%s'" %
    #         object['name'])

    invalidChars = set(string.punctuation.replace("-", ""))
    if any(char in invalidChars for char in object['name']):
        errors.append('ERROR: No special characters allowed in name for object: %s' % object['name'])

    try:
        object['description'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("ERROR: description not ascii for object: %s" % object['name'])

    if 'how_to_implement' in object:
        try:
            object['how_to_implement'].encode('ascii')
        except UnicodeEncodeError:
            errors.append('ERROR: how_to_implement not ascii for object: %s' % object['name'])

    try:
        datetime.datetime.strptime(object['date'], '%Y-%m-%d')
    except ValueError:
        errors.append("ERROR: Incorrect date format, should be YYYY-MM-DD for object: %s" % object['name'])

    # logic for handling risk related tags which are a triple of k/v pairs
    # risk_object, risk_object_type and risk_score
    # the first two fields risk_object, and risk_object_type are an enum of fixed values
    # defined by ESCU risk scoring

    if 'tags' in object:
        # check product tag is present in all objects
        if 'product' not in object['tags']:
            errors.append("ERROR: a `product` tag is required for object: %s" % object['name'])

        # check detections have mitre_ids
        if 'search' in object and 'known_false_positives' in object:
            if 'mitre_attack_id' not in object['tags']:
                errors.append("ERROR: a `mitre_attack_id` tag is required detection object: %s" % object['name'])

        for k,v in object['tags'].items():

            if k == 'risk_score':
                if not isinstance(v, int):
                    errors.append("ERROR: risk_score not integer value for object: %s" % v)
            risk_object_type = ["user","system", "other"]

            if k == 'risk_object_type':
                if v not in risk_object_type:
                    errors.append("ERROR: risk_object_type can only contain user, system, other: %s" % v)

            if k == 'risk_object':
                try:
                    v.encode('ascii')
                except UnicodeEncodeError:
                    errors.append("ERROR: risk_object not ascii for object: %s" % v)

    return errors, uuids


def validate_detection_search(object, macros):
    errors = []

    if not '_filter' in object['search']:
        errors.append("ERROR: Missing filter for detection: " + object['name'])

    filter_macro = re.search("([a-z0-9_]*_filter)", object['search'])

    if filter_macro and filter_macro.group(1) != (object['name'].replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter') and "input_filter" not in filter_macro.group(1):
        errors.append("ERROR: filter for detection: " + object['name'] + " needs to use the name of the detection in lowercase and the special characters needs to be converted into _ .")

    if any(x in object['search'] for x in ['eventtype=', 'sourcetype=', ' source=', 'index=']):
        if not 'index=_internal' in object['search']:
            errors.append("ERROR: Use source macro instead of eventtype, sourcetype, source or index in detection: " + object['name'])

    macros_found = re.findall('\`([^\s]+)`',object['search'])
    macros_filtered = []
    for macro in macros_found:
        if not '_filter' in macro and not 'security_content_ctime' in macro and not 'drop_dm_object_name' in macro and not 'cim_' in macro and not 'get_' in macro:
            macros_filtered.append(macro)

    for macro in macros_filtered:
        found_macro = False
        for macro_obj in macros:
            if macro_obj['name'] == macro:
                found_macro = True

        if not found_macro:
            errors.append("ERROR: macro definition for " + macro + " can't be found for detection " + object['name'])

    return errors

def validate_baseline_search(object, macros):
    errors = []

    if any(x in object['search'] for x in ['eventtype=', 'sourcetype=', ' source=', 'index=']):
        if not 'index=_internal' in object['search']:
            errors.append("ERROR: Use source macro instead of eventtype, sourcetype, source or index in detection: " + object['name'])

    macros_found = re.findall('\`([^\s]+)`',object['search'])
    macros_filtered = []
    for macro in macros_found:
        if not '_filter' in macro and not 'security_content_ctime' in macro and not 'drop_dm_object_name' in macro and not 'cim_' in macro and not 'get_' in macro:
            macros_filtered.append(macro)

    for macro in macros_filtered:
        found_macro = False
        for macro_obj in macros:
            if macro_obj['name'] == macro:
                found_macro = True

        if not found_macro:
            errors.append("ERROR: macro definition for " + macro + " can't be found for detection " + object['name'])

    return errors


def validate_lookups_content(REPO_PATH, lookup_path, lookup):
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

    validation_objects = ['macros','lookups','stories','detections','baselines','response_tasks','responses','deployments']

    objects = {}
    schema_error = False
    schema_errors = []

    for validation_object in validation_objects:
        objects, error, errors = validate_schema(REPO_PATH, validation_object, objects)
        schema_error = schema_error or error
        if len(errors) > 0:
            schema_errors = schema_errors + errors

    validation_errors = validate_objects(REPO_PATH, objects, verbose)

    schema_errors = schema_errors + validation_errors

    for schema_error in schema_errors:
        print(schema_error)

    if schema_error or len(schema_errors) > 0:
        sys.exit("Errors found")
    else:
        print("No Errors found")
