#!/usr/bin/python

'''
Validates Manifest file under the security-content repo for correctness.
'''

import glob
import json
import jsonschema
import sys
import argparse
from os import path


def validate_story(REPO_PATH, verbose):
    ''' Validates Stories'''

    # retrive
    v1_schema_file = path.join(path.expanduser(REPO_PATH), 'spec/v1/analytic_story.json.spec')
    try:
        v1_schema = json.loads(open(v1_schema_file, 'rb').read())
    except IOError:
        print "Error reading version 1 story schema file {0}".format(v1_schema_file)

    v2_schema_file = path.join(path.expanduser(REPO_PATH), 'spec/v2/story.spec.json')
    try:
        v2_schema = json.loads(open(v2_schema_file, 'rb').read())
    except IOError:
        print "Error reading version 2 story schema file {0}".format(v2_schema_file)

    error = False
    story_manifest_files = path.join(path.expanduser(REPO_PATH), "stories/*.json")

    for story_manifest_file in glob.glob(story_manifest_files):
        if verbose:
            print "processing story {0}".format(story_manifest_file)

        # read in each story
        try:
            story = json.loads(
                open(story_manifest_file, 'r').read())
        except IOError:
            print "Error reading {0}".format(story_manifest_file)
            error = True
            continue

        # validate v1 stories
        if story['spec_version'] == 1:
            try:
                jsonschema.validate(instance=story, schema=v1_schema)
            except jsonschema.exceptions.ValidationError as json_ve:
                print story_manifest_file
                print json_ve.message
                error = True
                continue

        elif story['spec_version'] == 2:
            try:
                jsonschema.validate(instance=story, schema=v2_schema)
            except jsonschema.exceptions.ValidationError as json_ve:
                print story_manifest_file
                print json_ve.message
                error = True
                continue

        else:
            print "Story: {0} does not contain a spec_version which is required".format(story_manifest_file)
            error = True
            continue

    return error


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="validates security content manifest files", epilog="""
        Validates security manifest for correctness, adhering to spec and other common items.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-security content repo")
    parser.add_argument("-v", "--verbose", required=False, action='store_true', help="prints verbose output")
    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    verbose = args.verbose

    error = validate_story(REPO_PATH, verbose)

    if error:
        sys.exit("Errors found")
    else:
        print "No errors found"
