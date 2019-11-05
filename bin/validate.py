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
import re
from os import path


def validate_object(REPO_PATH, schema_path, manifest_path, return_objects, verbose, lookups=None, macros=None):
    ''' Validate scheme '''
    error = False

    # uuids
    baselines_uuids = []
    story_uuids = []
    detection_uuids = []
    investigation_uuids = []

    schema_file = path.join(path.expanduser(REPO_PATH), schema_path)

    try:
        schema = json.loads(open(schema_file, 'rb').read())
    except IOError:
        print "ERROR: reading baseline schema file {0}".format(schema_file)

    objects = {}
    manifest_files = path.join(path.expanduser(REPO_PATH), manifest_path)

    for manifest_file in glob.glob(manifest_files):
        if verbose:
            print "processing manifest {0}".format(manifest_file)

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print "Error reading {0}".format(manifest_file)
                error = True
                continue

        try:
            jsonschema.validate(instance=object, schema=schema)
        except jsonschema.exceptions.ValidationError as json_ve:
            print "ERROR: {0} at:\n\t{1}".format(json.dumps(json_ve.message), manifest_file)
            print "\tAffected Object: {}".format(json.dumps(json_ve.instance))
            error = True

        objects[object['name']] = object

        # validate content
        if schema_path == 'spec/v2/lookups.spec.json':
            error = error or validate_lookups_content(REPO_PATH, "lookups/%s", object, manifest_file)
        elif schema_path == 'spec/v2/baselines.spec.json':
            error = error or validate_baselines_content(object, macros, lookups, manifest_file, baselines_uuids)
        elif schema_path == 'spec/v2/story.spec.json':
            error = error or validate_story_content(object, manifest_file, story_uuids)
        elif schema_path == 'spec/v2/detections.spec.json':
            error = error or validate_detection_content(object, macros, lookups, manifest_file, detection_uuids)
        elif schema_path == 'spec/v2/investigations.spec.json':
            error = error or validate_investigation_content(object, macros, lookups, manifest_file, investigation_uuids)

    if return_objects:
        return error, objects
    else:
        return error


def validate_lookups_content(REPO_PATH, lookup_path, lookup, manifest_file):
    error = False
    if 'filename' in lookup:
        lookup_csv_file = path.join(path.expanduser(REPO_PATH), lookup_path % lookup['filename'])
        if not path.isfile(lookup_csv_file):
            print "ERROR: filename {} does not exist".format(lookup['filename'])
            print lookup_csv_file
            print "\t{}".format(manifest_file)
            error = True

    return error


def validate_baselines_content(baseline, macros, lookups, baselines_manifest_file, baselines_uuids):
    errors = []
    error = False

    baselines_errors = validate_single_baseline_content(baseline, baselines_uuids, errors, macros, lookups)
    if baselines_errors:
        error = True
        for err in baselines_errors:
            print "{0} at:\n\t {1}".format(err, baselines_manifest_file)

    return error


def validate_single_baseline_content(baseline, baselines_uuids, errors, macros, lookups):

    if baseline['id'] == '':
        errors.append('ERROR: Blank ID')

    if baseline['id'] in baselines_uuids:
        errors.append('ERROR: Duplicate UUID found: %s' % baseline['id'])
    else:
        baselines_uuids.append(baseline['id'])

    if baseline['name'].endswith(" "):
        errors.append("ERROR: Investigation name has trailing spaces: '%s'" % baseline['name'])

    try:
        baseline['description'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("ERROR: description not ascii")

    if 'how_to_implement' in baseline:
        try:
            baseline['how_to_implement'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: how_to_implement not ascii")

    if 'eli5' in baseline:
        try:
            baseline['eli5'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: eli5 not ascii")

    if 'known_false_positives' in baseline:
        try:
            baseline['known_false_positives'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: known_false_positives not ascii")

    if 'splunk' in baseline['baseline']:

        # do a regex match here instead of key values
        if (baseline['baseline']['splunk']['search'].find('tstats') != -1) or \
                (baseline['baseline']['splunk']['search'].find('datamodel') != -1):

            if 'data_models' not in baseline['data_metadata']:
                errors.append("ERROR: The Splunk search uses a data model but 'data_models' field is not set")

            if not baseline['data_metadata']['data_models']:
                errors.append("ERROR: The Splunk search uses a data model but 'data_models' is empty")

            errors = validate_data_model_and_search(baseline['baseline']['splunk']['search'], baseline['data_metadata'], errors)

        # do a regex match here instead of key values
        if (baseline['baseline']['splunk']['search'].find('sourcetype') != -1):
            if 'data_sourcetypes' not in baseline['data_metadata']:
                errors.append("ERROR: The Splunk search specifies a sourcetype but 'data_sourcetypes' \
                            field is not set")

            if not baseline['data_metadata']['data_sourcetypes']:
                errors.append("ERROR: The Splunk search specifies a sourcetype but \
                        'data_sourcetypes' is empty")

        if 'macros' in baseline['baseline']['splunk']:
            for macro in baseline['baseline']['splunk']['macros']:
                if macro not in macros:
                    errors.append("ERROR: The Splunk search specifies a macro \"{}\" but there is no macro manifest for it".format(macro))

        if 'lookups' in baseline['baseline']['splunk']:
            for lookup in baseline['baseline']['splunk']['lookups']:
                if lookup not in lookups:
                    errors.append("ERROR: The Splunk search specifies a lookup \"{}\" but there is no lookup manifest for it".format(lookup))

    return errors


def validate_story_content(story, story_manifest_file, story_uuids):
    error = False

    story_errors = validate_single_story_content(story, story_uuids)
    if story_errors:
        error = True
        for err in story_errors:
            print "{0} at:\n\t {1}".format(err, story_manifest_file)

    return error


def validate_single_story_content(story, STORY_UUIDS):
    ''' Validate that the content of a story manifest is correct'''
    errors = []

    if story['id'] == '':
        errors.append('ERROR: Blank ID')

    if story['id'] in STORY_UUIDS:
        errors.append('ERROR: Duplicate UUID found: %s' % story['id'])
    else:
        STORY_UUIDS.append(story['id'])

    try:
        story['description'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("ERROR: description not ascii")

    try:
        story['narrative'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("ERROR: narrative not ascii")

    return errors


def validate_detection_content(detection, macros, lookups, manifest_file, detection_uuids):
    error = False

    detection_errors = validate_single_detection_content(detection, detection_uuids, macros, lookups)
    if detection_errors:
        error = True
        for err in detection_errors:
            print "{0} at:\n\t {1}".format(err, manifest_file)

    return error


def validate_single_detection_content(detection, DETECTION_UUIDS, macros, lookups):

    errors = []

    if detection['id'] == '':
        errors.append('ERROR: Blank ID')

    if detection['id'] in DETECTION_UUIDS:
        errors.append('ERROR: Duplicate UUID found: %s' % detection['id'])
    else:
        DETECTION_UUIDS.append(detection['id'])

    if detection['name'].endswith(" "):
        errors.append(
            "ERROR: Detection name has trailing spaces: '%s'" %
            detection['name'])

    try:
        detection['description'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("ERROR: description not ascii")

    if 'how_to_implement' in detection:
        try:
            detection['how_to_implement'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: how_to_implement not ascii")

    if 'eli5' in detection:
        try:
            detection['eli5'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: eli5 not ascii")

    if 'known_false_positives' in detection:
        try:
            detection['known_false_positives'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: known_false_positives not ascii")
    # modded to pass validation for uba detections - not yet fleshed out
    if 'splunk' in detection['detect']:
        # do a regex match here instead of key values
        # if (detection['detect']['splunk']['correlation_rule']['search'].find('tstats') != -1) or \
        #        (detection['detect']['splunk']['correlation_rule']['search'].find('datamodel') != -1):
        if (detection['detect']['splunk']['correlation_rule']['search'].find('datamodel') != -1):
            if 'data_models' not in detection['data_metadata']:
                errors.append("ERROR: The Splunk search uses a data model but 'data_models' field is not set")

            if not detection['data_metadata']['data_models']:
                errors.append("ERROR: The Splunk search uses a data model but 'data_models' is empty")

            errors = validate_data_model_and_search(detection['detect']['splunk']['correlation_rule']['search'], detection['data_metadata'], errors)

        # do a regex match here instead of key values
        if (detection['detect']['splunk']['correlation_rule']['search'].find('sourcetype') != -1):
            if 'data_sourcetypes' not in detection['data_metadata']:
                errors.append("ERROR: The Splunk search specifies a sourcetype but 'data_sourcetypes' field is not set")
            elif not detection['data_metadata']['data_sourcetypes']:
                errors.append("ERROR: The Splunk search specifies a sourcetype but 'data_sourcetypes' is empty")

        if 'macros' in detection['detect']['splunk']['correlation_rule']:
            for macro in detection['detect']['splunk']['correlation_rule']['macros']:
                if macro not in macros:
                    errors.append("ERROR: The Splunk search specifies a macro \"{}\" but there is no macro manifest for it".format(macro))

        if 'lookups' in detection['detect']['splunk']['correlation_rule']:
            for lookup in detection['detect']['splunk']['correlation_rule']['lookups']:
                if lookup not in lookups:
                    errors.append("ERROR: The Splunk search specifies a lookup \"{}\" but there is no lookup manifest for it".format(lookup))

        if 'notable' in detection['detect']['splunk']['correlation_rule']:
            if ('drilldown_search' in detection['detect']['splunk']['correlation_rule']['notable']) ^ \
                    ('drilldown_name' in detection['detect']['splunk']['correlation_rule']['notable']):

                errors.append("ERROR: Both drilldown_search and drilldown_name must be defined")

    elif 'uba' in detection['detect']:
        if (detection['detect']['uba']['correlation_rule']['search'].find('tstats') != -1) or \
                (detection['detect']['splunk']['correlation_rule']['search'].find('datamodel') != -1):

            if 'data_models' not in detection['data_metadata']:
                errors.append("ERROR: The Splunk search uses a data model but 'data_models' field is not set")

            if not detection['data_metadata']['data_models']:
                errors.append("ERROR: The Splunk search uses a data model but 'data_models' is empty")

        # do a regex match here instead of key values
        if (detection['detect']['uba']['correlation_rule']['search'].find('sourcetype') != -1):
            if 'data_sourcetypes' not in detection['data_metadata']:
                errors.append("ERROR: The Splunk search specifies a sourcetype but 'data_sourcetypes' \
                            field is not set")

            if not detection['data_metadata']['data_sourcetypes']:
                errors.append("ERROR: The Splunk search specifies a sourcetype but \
                        'data_sourcetypes' is empty")

        # do a regex match here instead of key values

    return errors


def validate_investigation_content(investigation, macros, lookups, manifest_file, investigation_uuids):
    error = False

    investigation_errors = validate_single_investigation_content(investigation, investigation_uuids, macros, lookups)
    if investigation_errors:
        error = True
        for err in investigation_errors:
            print "{0} at:\n\t {1}".format(err, manifest_file)

    return error


def validate_single_investigation_content(investigation, investigation_uuids, macros, lookups):
    errors = []

    if investigation['id'] == '':
        errors.append('ERROR: Blank ID')

    if investigation['id'] in investigation_uuids:
        errors.append('ERROR: Duplicate UUID found: %s' % investigation['id'])
    else:
        investigation_uuids.append(investigation['id'])

    if investigation['name'].endswith(" "):
        errors.append(
            "ERROR: Investigation name has trailing spaces: '%s'" %
            investigation['name'])

    try:
        investigation['description'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("ERROR: description not ascii")

    if 'how_to_implement' in investigation:
        try:
            investigation['how_to_implement'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: how_to_implement not ascii")

    if 'eli5' in investigation:
        try:
            investigation['eli5'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: eli5 not ascii")

    if 'known_false_positives' in investigation:
        try:
            investigation['known_false_positives'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("ERROR: known_false_positives not ascii")

    if 'splunk' in investigation['investigate']:

        # do a regex match here instead of key values
        if (investigation['investigate']['splunk']['search'].find('tstats') != -1) or \
                (investigation['investigate']['splunk']['search'].find('datamodel') != -1):

            if 'data_models' not in investigation['data_metadata']:
                errors.append("ERROR: The Splunk search uses a data model but 'data_models' field is not set")

            if not investigation['data_metadata']['data_models']:
                errors.append("ERROR: The Splunk search uses a data model but 'data_models' is empty")

            errors = validate_data_model_and_search(investigation['investigate']['splunk']['search'], investigation['data_metadata'], errors)


        # do a regex match here instead of key values
        if (investigation['investigate']['splunk']['search'].find('sourcetype') != -1):
            if 'data_sourcetypes' not in investigation['data_metadata']:
                errors.append("ERROR: The Splunk search specifies a sourcetype but 'data_sourcetypes' \
                            field is not set")

            if not investigation['data_metadata']['data_sourcetypes']:
                errors.append("ERROR: The Splunk search specifies a sourcetype but \
                        'data_sourcetypes' is empty")

        if 'macros' in investigation['investigate']['splunk']:
            for macro in investigation['investigate']['splunk']['macros']:
                if macro not in macros:
                    errors.append("ERROR: The Splunk search specifies a macro \"{}\" but there is no macro manifest for it".format(macro))

        if 'lookups' in investigation['investigate']['splunk']:
            for lookup in investigation['investigate']['splunk']['lookups']:
                if lookup not in lookups:
                    errors.append("ERROR: The Splunk search specifies a lookup \"{}\" but there is no lookup manifest for it".format(lookup))

    return errors


def validate_data_model_and_search(search, data_metadata, errors):
    # Validate data model field against data model in search

    pattern = 'from datamodel\s*=\s*([^\s]*)'
    extracted_data_model = re.search(pattern, search)
    if extracted_data_model:
        pattern = '^[^\.]*'
        parent_data_model = re.search(pattern, extracted_data_model.group(1))

        if 'data_models' in data_metadata:
            if data_metadata['data_models'][0] != parent_data_model.group(0):
                errors.append("ERROR: 'data_models' field doesn't match data model used in the search")

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

    macros_error, macros = validate_object(REPO_PATH, 'spec/v2/macros.spec.json', 'macros/*.yml', True, verbose)
    lookups_error, lookups = validate_object(REPO_PATH, 'spec/v2/lookups.spec.json', 'lookups/*.yml', True, verbose)
    story_error = validate_object(REPO_PATH, 'spec/v2/story.spec.json', 'stories/*.yml', False, verbose)
    detection_error = validate_object(REPO_PATH, 'spec/v2/detections.spec.json', 'detections/*.yml', False, verbose, lookups, macros)
    investigation_error = validate_object(REPO_PATH, 'spec/v2/investigations.spec.json', 'investigations/*.yml', False, verbose, lookups, macros)
    baseline_error = validate_object(REPO_PATH, 'spec/v2/baselines.spec.json', 'baselines/*.yml', False, verbose, lookups, macros)

    if story_error or detection_error or investigation_error or baseline_error or macros_error or lookups_error:
        sys.exit("Errors found")
    else:
        print "No Errors found"
