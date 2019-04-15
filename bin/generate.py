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


def process_data_metadata(obj, complete_obj, name):

    # collect tagging
    metadata = obj['data_metadata']
    if 'data_models' in metadata:
        complete_obj[name]['data_models'] = metadata['data_models']
    if 'providing_technologies' in metadata:
        complete_obj[name]['providing_technologies'] = metadata['providing_technologies']
    if 'data_source' in metadata:
        complete_obj[name]['data_source'] = metadata['data_source']

    if 'mappings' in obj:
        complete_obj[name]['mappings'] = obj['mappings']
    if 'fields_required' in obj:
        complete_obj[name]['entities'] = obj['fields_required']
    if 'entities' in obj:
        complete_obj[name]['entities'] = obj['entities']

    return complete_obj


def generate_baselines(REPO_PATH, detections):
    # first we process detections

    baselines = []
    baselines_manifest_files = path.join(path.expanduser(REPO_PATH), "baselines/*.json")
    for baselines_manifest_file in glob.glob(baselines_manifest_files):
        # read in each story
        try:
            baseline = json.loads(
                open(baselines_manifest_file, 'r').read())
        except IOError:
            print "ERROR: reading {0}".format(baselines_manifest_file)
            continue
        baselines.append(baseline)

    complete_baselines = dict()
    for baseline in baselines:

        # lets process v1 baseline
        if baseline['spec_version'] == 1:
            if verbose:
                print "processing v1 baseline: {0}".format(baseline['search_name'])
            name = baseline['search_name']
            id = baseline['search_id']

            # grab search information
            search = baseline['search']
            schedule = baseline['scheduling']
            earliest_time = schedule['earliest_time']
            latest_time = schedule['latest_time']
            if 'cron_schedule' in schedule:
                cron = schedule['cron_schedule']
            else:
                cron = ''

            if baseline['spec_version'] == 2:
                if verbose:
                    print "processing v2 baseline: {0}".format(baseline['name'])
                name = baseline['name']
                id = baseline['id']

                # splunk
                if baseline['baseline'] == 'splunk':
                    splunk = baseline['baseline']
                    search = splunk['search']
                    earliest_time = splunk['earliest_time']
                    latest_time = splunk['latest_time']
                    cron = splunk['cron']

        complete_baselines[name] = {}
        complete_baselines[name]['baseline_name'] = name
        complete_baselines[name]['id'] = id
        complete_baselines[name]['search'] = search
        complete_baselines[name]['latest_time'] = latest_time
        complete_baselines[name]['earliest_time'] = earliest_time
        complete_baselines[name]['cron'] = cron

        # process its metadata
        complete_baselines = process_data_metadata(baseline, complete_baselines, name)

        # baselines associated with the detections
        complete_baselines[name]['detections'] = []
        for detection_name, detection in sorted(detections.iteritems()):
            complete_baselines[name]['detections'].append(detection['detection_name'])
    return complete_baselines


def generate_investigations(REPO_PATH, detections):
    # first we process detections

    investigations = []
    investigations_manifest_files = path.join(path.expanduser(REPO_PATH), "investigations/*.json")
    for investigations_manifest_file in glob.glob(investigations_manifest_files):
        # read in each story
        try:
            investigation = json.loads(
                open(investigations_manifest_file, 'r').read())
        except IOError:
            print "ERROR: reading {0}".format(investigations_manifest_file)
            continue
        investigations.append(investigation)

    complete_investigations = dict()
    for investigation in investigations:

        # lets process v1 investigation
        if investigation['spec_version'] == 1:
            if verbose:
                print "processing v1 investigation: {0}".format(investigation['search_name'])
            name = investigation['search_name']
            id = investigation['search_id']

            # grab search information
            search = investigation['search']
            schedule = investigation['search_window']
            earliest_time = schedule['earliest_time_offset']
            latest_time = schedule['latest_time_offset']
            cron = ''

            if investigation['spec_version'] == 2:
                if verbose:
                    print "processing v2 investigation: {0}".format(investigation['name'])
                name = investigation['name']
                id = investigation['id']

                # splunk
                if investigation['investigate'] == 'splunk':
                    splunk = investigation['investigate']
                    search = splunk['search']
                    earliest_time = splunk['earliest_time']
                    latest_time = splunk['latest_time']
                    cron = splunk['cron']

        complete_investigations[name] = {}
        complete_investigations[name]['investigation_name'] = name
        complete_investigations[name]['id'] = id
        complete_investigations[name]['search'] = search
        complete_investigations[name]['latest_time'] = latest_time
        complete_investigations[name]['earliest_time'] = earliest_time
        complete_investigations[name]['cron'] = cron

        # process its metadata
        complete_investigations = process_data_metadata(investigation, complete_investigations, name)

        # investigations associated with the detections
        complete_investigations[name]['detections'] = []
        for detection_name, detection in sorted(detections.iteritems()):
            complete_investigations[name]['detections'].append(detection['detection_name'])
    return complete_investigations


def generate_detections(REPO_PATH, stories):
    # first we process detections

    detections = []
    detections_manifest_files = path.join(path.expanduser(REPO_PATH), "detections/*.json")
    for detections_manifest_file in glob.glob(detections_manifest_files):
        # read in each story
        try:
            detection = json.loads(
                open(detections_manifest_file, 'r').read())
        except IOError:
            print "ERROR: reading {0}".format(detections_manifest_file)
            continue
        detections.append(detection)

    complete_detections = dict()
    for detection in detections:

        # lets process v1 detections
        if detection['spec_version'] == 1:
            if verbose:
                print "processing v1 detection: {0}".format(detection['search_name'])
            name = detection['search_name']
            id = detection['search_id']

            # grab search information
            search = detection['search']
            schedule = detection['scheduling']
            earliest_time = schedule['earliest_time']
            latest_time = schedule['latest_time']
            cron = schedule['cron_schedule']

        # lets process v2 detections
        if detection['spec_version'] == 2:
            if verbose:
                print "processing v2 detection: {0}".format(detection['name'])
            name = detection['name']
            id = detection['id']

            # splunk
            if detection['detect'] == 'splunk':
                splunk = detection['detect']
                search = splunk['search']
                earliest_time = splunk['earliest_time']
                latest_time = splunk['latest_time']
                cron = splunk['cron']

            # uba
            if detection['detect'] == 'uba':
                uba = detection['detect']
                search = uba['search'] = 'CONSTRUCT DETECTION SEARCH HERE'
                earliest_time = uba['earliest_time']
                latest_time = uba['latest_time']
                cron = uba['cron']

            # phantom
            if detection['detect'] == 'phantom':
                phantom = detection['detect']
                search = phantom['search'] = 'CONSTRUCT DETECTION SEARCH HERE'
                earliest_time = phantom['earliest_time']
                latest_time = phantom['latest_time']
                cron = phantom['cron']

        complete_detections[name] = {}
        complete_detections[name]['detection_name'] = name
        complete_detections[name]['id'] = id
        complete_detections[name]['search'] = search
        complete_detections[name]['latest_time'] = latest_time
        complete_detections[name]['earliest_time'] = earliest_time
        complete_detections[name]['cron'] = cron

        # process its metadata
        complete_detections = process_data_metadata(detection, complete_detections, name)

        # stories associated with the detection
        complete_detections[name]['stories'] = []
        for story_name, story in sorted(stories.iteritems()):
            for d in story['detections']:
                if d['name'] == name:
                    complete_detections[name]['stories'].append(story['story_name'])

    return complete_detections


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
        complete_stories[story['name']]['spec_version'] = story['spec_version']

        # grab searches
        if story['spec_version'] == 1:
            if 'detection_searches' in story['searches']:
                detections = []
                for d in story['searches']['detection_searches']:
                    detections.append({"type": "splunk", "name": d})
                complete_stories[story['name']]['detections'] = detections

            if 'support_searches' in story['searches']:
                baselines = []
                for b in story['searches']['support_searches']:
                    detections.append({"type": "splunk", "name": b})
                complete_stories[story['name']]['baselines'] = baselines

            investigations = []
            if 'contexual_searches' in story['searches']:
                for i in story['searches']['contexual_searches']:
                    investigations.append({"type": "splunk", "name": i})
            if 'investigative_searches' in story['searches']:
                for i in story['searches']['investigative_searches']:
                    investigations.append({"type": "splunk", "name": i})
            complete_stories[story['name']]['investigations'] = investigations

        if story['spec_version'] == 2:
            if 'detections' in story:
                detections = []
                for d in story['detections']:
                    detections.append({"type": d['type'], "name": d['name']})
                complete_stories[story['name']]['detections'] = detections

            if 'baselines' in story:
                baselines = []
                for b in story['baselines']:
                    detections.append({"type": d['type'], "name": b['name']})
                complete_stories[story['name']]['baselines'] = baselines

            if 'investigations' in story:
                investigations = []
                for i in story['investigations']:
                    investigations.append({"type": i['type'], "name": i['name']})
            complete_stories[story['name']]['investigations'] = investigations

    return complete_stories


def write_analytics_story_conf(stories, detections, investigations, baselines, OUTPUT_DIR):

    # Create conf files from analytics stories files
    story_output_path = OUTPUT_DIR + "/default/analytics_stories.conf"
    output_file = open(story_output_path, 'w')

    # Finish the story
    for story_name, story in sorted(stories.iteritems()):
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
    complete_detections = generate_detections(REPO_PATH, complete_stories)
    complete_investigations = generate_investigations(REPO_PATH, complete_detections)
    complete_baselines = generate_baselines(REPO_PATH, complete_detections)
    # complete_responses = generate_responses(REPO_PATH, complete_responses)
    story_count, story_path = write_analytics_story_conf(complete_stories, complete_detections,
                                                         complete_investigations, complete_baselines, OUTPUT_DIR)
    print "{0} stories have been successfully to {1}".format(story_count, story_path)

    # detection_count, detection_path = write_savedsearches_conf(complete_stories, complete_detections, complete_investigations,
    #                                                     OUTPUT_DIR)
    # print "{0} stories have been successfully to {1}".format(detection_count, detection_path)
