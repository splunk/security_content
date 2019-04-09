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


def generate_savedsearches(REPO_PATH, stories):
    # first we process detections

    # detections_files = []
    # detections_manifest_files = path.join(path.expanduser(REPO_PATH), "detections/*.json")

    for story_name, story in stories.iteritems():
        if 'detections' in story:

            search_manifests = {}
            for search_manifest_file in glob.glob(path.join(REPO_PATH, '*/detections/*.json')):
                try:
                    search_manifest = json.loads(open(search_manifest_file, 'r').read())
                except Exception as e:
                    print "Error reading %s" % search_manifest_file
                    print e
                    continue

                search_manifests[search_manifest['search_name']] = search_manifest

    # story['mappings'] =
    # complete_stories[story['name']]['mappings'] = {}
    # complete_stories[story['name']]['data_models'] = set()
    # complete_stories[story['name']]['providing_technologies'] = set()


def generate_analytics_story(REPO_PATH, verbose):
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
        complete_stories[story['name']]['narrative'] = story['narrative']

        # grab searches
        if story['spec_version'] == 1:
            if 'detection_searches' in story['searches']:
                detections = []
                for d in story['searches']['detection_searches']:
                    detections.append({"type": "splunk", "name": "ESCU - " + d + " - Rule"})
                complete_stories[story['name']]['detections'] = detections

            if 'support_searches' in story['searches']:
                baselines = []
                for b in story['searches']['support_searches']:
                    detections.append({"type": "splunk", "name": "ESCU - " + b})
                complete_stories[story['name']]['baselines'] = baselines

            investigations = []
            if 'contexual_searches' in story['searches']:
                for i in story['searches']['contexual_searches']:
                    investigations.append({"type": "splunk", "name": "ESCU - " + i})
            if 'investigative_searches' in story['searches']:
                for i in story['searches']['investigative_searches']:
                    investigations.append({"type": "splunk", "name": "ESCU - " + i})
            complete_stories[story['name']]['investigations'] = investigations

        if story['spec_version'] == 2:
            if 'detections' in story:
                detections = []
                for d in story['detections']:
                    detections.append({"type": d['type'], "name": "ESCU - " + d['name'] + " - Rule"})
                complete_stories[story['name']]['detections'] = detections

            if 'baselines' in story:
                baselines = []
                for b in story['baselines']:
                    detections.append({"type": d['type'], "name": "ESCU - " + b['name']})
                complete_stories[story['name']]['baselines'] = baselines

            if 'investigations' in story:
                investigations = []
                for i in story['investigations']:
                    investigations.append({"type": i['type'], "name": "ESCU - " + i['name']})
            complete_stories[story['name']]['investigations'] = investigations

    return complete_stories


def write_story_output(complete_stories, OUTPUT_DIR):

    # Create conf files from analytics stories files
    story_output_path = OUTPUT_DIR + "/default/analytics_stories.conf"
    output_file = open(story_output_path, 'w')

    # Finish the story
    for story_name, story in sorted(complete_stories.iteritems()):
        output_file.write("[%s]\n" % story_name)
        output_file.write("category = %s\n" % story['category'])
        output_file.write("creation_date = %s\n" % story['creation_date'])
        output_file.write("modification_date = %s\n" % story['modification_date'])
        output_file.write("id = %s\n" % story['id'])
        output_file.write("version = %s\n" % story['version'])
        output_file.write("reference = %s\n" % json.dumps(story['references']))

        if 'detections' in story:
            output_file.write("detections = %s\n" % json.dumps(story['detections']))
        if 'investigations' in story:
            output_file.write("investigations = %s\n" % json.dumps(story['investigations']))
        if 'baselines' in story:
            output_file.write("baselines = %s\n" % json.dumps(story['baselines']))

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
    story_count = len(complete_stories.keys())
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

    complete_stories = generate_analytics_story(REPO_PATH, verbose)
    # generate_detections(REPO_PATH, complete_stories)
    story_count, story_path = write_story_output(complete_stories, OUTPUT_DIR)
    print "{0} stories have been successfully to {1}".format(story_count, story_path)
