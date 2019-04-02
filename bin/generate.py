#!/usr/bin/python

'''
Generates splunk configurations from manifest files under the security-content repo.
'''

import glob
import json
import argparse
from os import path

ALL_UUIDS = []


def markdown(x):
    markdown = str(x)
    markdown = markdown.replace("<code>", "`")
    markdown = markdown.replace("</code>", "`")
    markdown = markdown.replace("<b>", "**")
    markdown = markdown.replace("</b>", "**")
    # list tag replacements
    markdown = markdown.replace("<ol><li>", "\\\n\\\n1. ")
    markdown = markdown.replace("</li><li>", "\\\n\\\n1. ")
    markdown = markdown.replace("</li></ol>", "")
    markdown = markdown.replace("</li></ul>", "")
    markdown = markdown.replace("<ul><li>", "\\\n\\\n1. ")
    # break tags replacements
    markdown = markdown.replace("<br></br>", "\\\n\\\n")
    markdown = markdown.replace("<br/><br/>", "\\\n\\\n")
    markdown = markdown.replace("<br/>", "\\\n\\\n")
    return markdown


def generate_analytics_story(REPO_PATH, OUTPUT_DIR, verbose):

    # Create conf files from analytics stories files
    story_output_path = OUTPUT_DIR + "/default/analytics_stories.conf"
    output_file = open(story_output_path, 'w')

    story_files = []
    story_manifest_files = path.join(path.expanduser(REPO_PATH), "stories/*.json")

    for story_manifest_file in glob.glob(story_manifest_files):
        # read in each story
        try:
            story = json.loads(
                open(story_manifest_file, 'r').read())
        except IOError:
            print "ERROR: reading {0}".format(story_manifest_file)
            continue
        story_files.append(story)

    # store an object with all stories and their data
    complete_stories = dict()
    for story in story_files:
        if verbose:
            print "processing story: {0}".format(story['name'])
        # Start building the story for the use case
        complete_stories[story['name']] = {}
        complete_stories[story['name']]['story_name'] = story['name']
        complete_stories[story['name']]['id'] = story['id']

        # grab modification date if it has one, otherwise write as creation date
        if 'modification_date' in story:
            complete_stories[story['name']]['modification_date'] = story['modification_date']
            complete_stories[story['name']]['creation_date'] = story['creation_date']
        else:
            complete_stories[story['name']]['modification_date'] = story['creation_date']
            complete_stories[story['name']]['creation_date'] = story['creation_date']

        complete_stories[story['name']]['description'] = story['description']
        if 'references' not in story:
            story['references'] = []
        complete_stories[story['name']]['references'] = story['references']
        complete_stories[story['name']]['category'] = story['category']
        complete_stories[story['name']]['version'] = story['version']
        complete_stories[story['name']]['mappings'] = {}
        complete_stories[story['name']]['data_models'] = set()
        complete_stories[story['name']]['providing_technologies'] = set()
        complete_stories[story['name']]['tags'] = set()
        complete_stories[story['name']]['narrative'] = story['narrative']

        complete_stories[story['name']]['detection_searches'] = []
        complete_stories[story['name']]['investigative_searches'] = []
        complete_stories[story['name']]['contextual_searches'] = []
        complete_stories[story['name']]['support_searches'] = []

    # Finish the story
    for story_name, story in sorted(complete_stories.iteritems()):
        output_file.write("[%s]\n" % story_name)
        output_file.write("category = %s\n" % story['category'])
        output_file.write("creation_date = %s\n" % story['creation_date'])
        output_file.write("modification_date = %s\n" % story['modification_date'])
        output_file.write("id = %s\n" % story['id'])
        output_file.write("version = %s\n" % story['version'])
        output_file.write("reference = %s\n" % json.dumps(story['references']))

        # REMOVE THIS FUNCTION MAKE SURE ALL DESCRIPTIONs ARE NATIVELY IN MARKDOWN
        description = markdown(story['description'])
        output_file.write("description = %s\n" % description)

        # REMOVE THIS FUNCTION MAKE SURE ALL NARRATIVE ARE NATIVELY IN MARKDOWN
        if story['narrative']:
            narrative = markdown(story['narrative'])
            output_file.write("narrative = %s\n" % narrative)
        output_file.write("\n")

    # close file, count stories we found and return
    output_file.close()
    story_count = len(story_files)
    return story_count, story_output_path


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="generates splunk conf files out of security-content manifests", epilog="""
    This tool converts manifests to the source files to be used by products like Splunk Enterprise.
    It generates the savesearches.conf, analytics_stories.conf files for ES.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-security content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory")
    parser.add_argument("-v", "--verbose", required=False, action='store_true', help="prints verbose output")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_DIR = args.output
    verbose = args.verbose

    story_count, story_path = generate_analytics_story(REPO_PATH, OUTPUT_DIR, verbose)
    print "{0} stories have been successfully to {1}".format(story_count, story_path)
