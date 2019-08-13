#!/usr/bin/python

'''
Generates splunk configurations from manifest files under the security-content repo.
'''

import glob
import json
import argparse
from os import path
import sys
import datetime

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


def process_investigation_stories(name, stories, detections):
    # grab stories
    # I hate myself for writing as much as you for reading it, a triple nested for loop :-(
    # but it works, if you would like to refactor be my guest :-)

    # version 2 stories
    investigation_stories = []
    for story_name, story in sorted(stories.iteritems()):
        for d in story['detections']:
            detection_investigations = detections[d['name']]['investigations']
            for i in detection_investigations:
                if i['name'] == name:
                    investigation_stories.append(story_name)

    # include version 1 stories
    for story_name, story in sorted(stories.iteritems()):
        if 'investigations' in story:
            for i in story['investigations']:
                if i['name'] == name:
                    investigation_stories.append(story_name)

    return sorted(set(investigation_stories))


def process_baseline_stories(name, stories, detections):
    # grab stories
    # I hate myself for writing as much as you for reading it, a triple nested for loop :-(
    # but it works, if you would like to refactor be my guest :-)

    # version 2 stories
    baseline_stories = []
    for story_name, story in sorted(stories.iteritems()):
        for d in story['detections']:
            detection_baselines = detections[d['name']]['baselines']
            for b in detection_baselines:
                if b['name'] == name:
                    baseline_stories.append(story_name)

    # include version 1 stories
    for story_name, story in sorted(stories.iteritems()):
        if 'baselines' in story:
            for b in story['baselines']:
                if b['name'] == name:
                    baseline_stories.append(story_name)

    return sorted(set(baseline_stories))


def generate_baselines(REPO_PATH, detections, stories):
    # first we process detections

    baselines = []
    baselines_manifest_files = path.join(path.expanduser(REPO_PATH), "baselines/*.json")
    for baselines_manifest_file in glob.glob(baselines_manifest_files):
        # read in each story
        try:
            baseline = json.loads(
                open(baselines_manifest_file, 'r').read())
        except IOError:
            sys.exit("ERROR: reading {0}".format(baselines_manifest_file))
        baselines.append(baseline)

    complete_baselines = dict()
    for baseline in baselines:

        # lets process v1 baseline
        if baseline['spec_version'] == 1:
            if verbose:
                print "processing v1 baseline: {0}".format(baseline['search_name'])
            name = baseline['search_name']
            type = 'splunk'
            id = baseline['search_id']
            description = baseline['search_description']

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
            description = baseline['description']

            # splunk
            if 'splunk' in baseline['baseline']:
                type = 'splunk'
                splunk = baseline['baseline']['splunk']
                search = splunk['search']
                earliest_time = splunk['schedule']['earliest_time']
                latest_time = splunk['schedule']['latest_time']
                cron = splunk['schedule']['cron_schedule']

        complete_baselines[name] = {}
        complete_baselines[name]['baseline_name'] = name
        complete_baselines[name]['id'] = id
        complete_baselines[name]['type'] = type
        complete_baselines[name]['description'] = description
        complete_baselines[name]['search'] = search
        complete_baselines[name]['latest_time'] = latest_time
        complete_baselines[name]['earliest_time'] = earliest_time
        complete_baselines[name]['cron'] = cron
        complete_baselines[name]['stories'] = process_baseline_stories(name, stories, detections)
        complete_baselines[name]['creation_date'] = baseline['creation_date']
        # set modification date to creation of there is not one
        if 'modification_date' in baseline:
            complete_baselines[name]['modification_date'] = baseline['modification_date']
        else:
            complete_baselines[name]['modification_date'] = baseline['creation_date']
        if 'how_to_implement' not in baseline:
            baseline['how_to_implement'] = ""
        complete_baselines[name]['how_to_implement'] = baseline['how_to_implement']
        if 'known_false_positives' not in baseline:
            baseline['known_false_positives'] = ""
        complete_baselines[name]['known_false_positives'] = baseline['known_false_positives']
        if 'eli5' not in baseline:
            baseline['eli5'] = ""
        complete_baselines[name]['eli5'] = baseline['eli5']

        # process its metadata
        complete_baselines = process_data_metadata(baseline, complete_baselines, name)

        # baselines associated with the detections and stories
        complete_baselines[name]['detections'] = []
        for detection_name, detection in sorted(detections.iteritems()):
            for b in detection['baselines']:
                if b['name'] == name:
                    complete_baselines[name]['detections'].append(detection['detection_name'])

    return complete_baselines


def generate_investigations(REPO_PATH, detections, stories):
    # first we process detections

    investigations = []
    investigations_manifest_files = path.join(path.expanduser(REPO_PATH), "investigations/*.json")
    for investigations_manifest_file in glob.glob(investigations_manifest_files):
        # read in each story
        try:
            investigation = json.loads(
                open(investigations_manifest_file, 'r').read())
        except IOError:
            sys.exit("ERROR: reading {0}".format(investigations_manifest_file))
        investigations.append(investigation)

    complete_investigations = dict()
    for investigation in investigations:

        # lets process v1 investigation
        if investigation['spec_version'] == 1:
            type = 'splunk'
            if verbose:
                print "processing v1 investigation: {0}".format(investigation['search_name'])
            name = investigation['search_name']
            id = investigation['search_id']
            description = investigation['search_description']

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
            description = investigation['description']

            # splunk
            if 'splunk' in investigation['investigate']:
                try:
                    type = 'splunk'
                    splunk = investigation['investigate']['splunk']
                    search = splunk['search']
                    earliest_time = splunk['schedule']['earliest_time']
                    latest_time = splunk['schedule']['latest_time']
                    cron = splunk['schedule']['cron_schedule']
                except KeyError as e:
                    sys.exit("ERROR: missing key {0} on {1} current object:\n{2}".format(e, name, splunk))

            # phantom
            if 'phantom' in investigation['investigate']:
                try:
                    type = 'phantom'
                    phantom = investigation['investigate']['phantom']
                    server = phantom['phantom_server']
                    playbook = phantom['playbook_name']
                    playbook_url = phantom['playbook_url']
                    earliest_time = phantom['schedule']['earliest_time']
                    latest_time = phantom['schedule']['latest_time']
                    cron = phantom['schedule']['cron_schedule']
                    search = 'CONSTRUCT DETECTION SEARCH HERE'
                except KeyError as e:
                    sys.exit("ERROR: \"{1}\" missing key {0} with error:\n{1}".format(e, name, e))

        complete_investigations[name] = {}
        complete_investigations[name]['investigation_name'] = name
        complete_investigations[name]['id'] = id
        complete_investigations[name]['type'] = type
        complete_investigations[name]['description'] = description
        complete_investigations[name]['search'] = search
        complete_investigations[name]['latest_time'] = latest_time
        complete_investigations[name]['earliest_time'] = earliest_time
        complete_investigations[name]['cron'] = cron
        complete_investigations[name]['creation_date'] = investigation['creation_date']
        complete_investigations[name]['stories'] = process_investigation_stories(name, stories, detections)
        # set modification date to creation of there is not one
        if 'modification_date' in investigation:
            complete_investigations[name]['modification_date'] = investigation['modification_date']
        else:
            complete_investigations[name]['modification_date'] = investigation['creation_date']
        if 'how_to_implement' not in investigation:
            investigation['how_to_implement'] = ""
        complete_investigations[name]['how_to_implement'] = investigation['how_to_implement']
        if 'known_false_positives' not in investigation:
            investigation['known_false_positives'] = "None at this time"
        complete_investigations[name]['known_false_positives'] = investigation['known_false_positives']
        # process its metadata
        complete_investigations = process_data_metadata(investigation, complete_investigations, name)

        if type == 'phantom':
            complete_investigations[name]['phantom_server'] = server
            complete_investigations[name]['playbook'] = playbook
            complete_investigations[name]['playbook_url'] = playbook_url

        # investigations associated with the detections and stories
        complete_investigations[name]['detections'] = []
        for detection_name, detection in sorted(detections.iteritems()):
            for i in detection['investigations']:
                if i['name'] == name:
                    complete_investigations[name]['detections'].append(detection['detection_name'])

        # grab detections
        for detection_name, detection in sorted(detections.iteritems()):
            for i in detection['investigations']:
                if i['name'] == name:
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
            sys.exit("ERROR: reading {0}".format(detections_manifest_file))
        detections.append(detection)

    complete_detections = dict()
    for detection in detections:
        # lets process v1 detections
        if detection['spec_version'] == 1:
            if verbose:
                print "processing v1 detection: {0}".format(detection['search_name'])
            name = detection['search_name']
            type = 'splunk'
            description = detection['search_description']
            id = detection['search_id']

            # grab search information
            correlation_rule = detection['correlation_rule']
            search = detection['search']
            schedule = detection['scheduling']
            earliest_time = schedule['earliest_time']
            latest_time = schedule['latest_time']
            cron = schedule['cron_schedule']

            # grabbing entities
            entities = []

            investigations = []
            baselines = []
            responses = []
            for story_name, story in sorted(stories.iteritems()):
                for d in story['detections']:
                    if d['name'] == name:
                        if 'investigations' in story:
                            investigations = story['investigations']
                        if 'baselines' in story:
                            baselines = story['baselines']

        # lets process v2 detections
        if detection['spec_version'] == 2:
            if verbose:
                print "processing v2 detection: {0}".format(detection['name'])
            name = detection['name']
            id = detection['id']
            entities = detection['entities']
            description = detection['description']

            # splunk
            if 'splunk' in detection['detect']:
                type = 'splunk'
                correlation_rule = detection['detect']['splunk']['correlation_rule']
                search = correlation_rule['search']
                earliest_time = correlation_rule['schedule']['earliest_time']
                latest_time = correlation_rule['schedule']['latest_time']
                cron = correlation_rule['schedule']['cron_schedule']

            # uba
            if 'uba' in detection['detect']:
                # uba = detection['detect']['uba']
                type = 'uba'
                correlation_rule = detection['detect']['uba']['correlation_rule']
                search = correlation_rule['search']
                earliest_time = correlation_rule['schedule']['earliest_time']
                latest_time = correlation_rule['schedule']['latest_time']
                cron = correlation_rule['schedule']['cron_schedule']

            # phantom
            if 'phantom' in detection['detect']:
                phantom = detection['detect']['phantom']
                type = 'phantom'
                search = phantom['search'] = 'CONSTRUCT DETECTION SEARCH HERE'
                # earliest_time = phantom['earliest_time']
                # latest_time = phantom['latest_time']
                # cron = phantom['cron_schedule']

            baselines = []
            investigations = []
            responses = []
            if 'baselines' in detection:
                for b in detection['baselines']:
                    baselines.append({"type": b['type'], "name": b['name']})
            if 'investigations' in detection:
                for i in detection['investigations']:
                    investigations.append({"type": i['type'], "name": i['name']})
            if 'responses' in detection:
                for r in detection['responses']:
                    responses.append({"type": r['type'], "name": r['name']})

        complete_detections[name] = {}
        complete_detections[name]['detection_name'] = name
        complete_detections[name]['id'] = id
        complete_detections[name]['search'] = search
        complete_detections[name]['latest_time'] = latest_time
        complete_detections[name]['earliest_time'] = earliest_time
        complete_detections[name]['cron'] = cron
        complete_detections[name]['investigations'] = investigations
        complete_detections[name]['baselines'] = baselines
        complete_detections[name]['responses'] = responses
        complete_detections[name]['entities'] = entities
        complete_detections[name]['description'] = description
        complete_detections[name]['correlation_rule'] = correlation_rule
        complete_detections[name]['type'] = type
        complete_detections[name]['maintainers'] = detection['maintainers']
        if 'references' not in detection:
            detection['references'] = []
        complete_detections[name]['references'] = detection['references']
        if 'channel' not in detection:
            detection['channel'] = ""
        complete_detections[name]['channel'] = detection['channel']
        if 'confidence' not in detection:
            detection['confidence'] = ""
        complete_detections[name]['confidence'] = detection['confidence']
        if 'eli5' not in detection:
            detection['eli5'] = ""
        complete_detections[name]['eli5'] = detection['eli5']
        if 'how_to_implement' not in detection:
            detection['how_to_implement'] = ""
        complete_detections[name]['how_to_implement'] = detection['how_to_implement']
        if 'asset_type' not in detection:
            detection['asset_type'] = ""
        complete_detections[name]['asset_type'] = detection['asset_type']
        if 'known_false_positives' not in detection:
            detection['known_false_positives'] = ""
        complete_detections[name]['known_false_positives'] = detection['known_false_positives']
        complete_detections[name]['security_domain'] = detection['security_domain']
        complete_detections[name]['version'] = detection['version']
        complete_detections[name]['spec_version'] = detection['spec_version']
        complete_detections[name]['creation_date'] = detection['creation_date']
        # set modification date to creation of there is not one
        if 'modification_date' in detection:
            complete_detections[name]['modification_date'] = detection['modification_date']
        else:
            complete_detections[name]['modification_date'] = detection['creation_date']

        # process its metadata
        complete_detections = process_data_metadata(detection, complete_detections, name)

        # stories associated with the detection
        complete_detections[name]['stories'] = []
        for story_name, story in sorted(stories.iteritems()):
            for d in story['detections']:
                if d['name'] == name:
                    complete_detections[name]['stories'].append(story['story_name'])

        # sort uniq the results
        complete_detections[name]['stories'] = sorted(set(complete_detections[name]['stories']))

    return complete_detections


def generate_stories(REPO_PATH, verbose):
    story_files = []
    story_manifest_files = path.join(path.expanduser(REPO_PATH), "stories/*.json")

    for story_manifest_file in glob.glob(story_manifest_files):
        # read in each story
        try:
            story = json.loads(
                open(story_manifest_file, 'r').read())
        except IOError:
            sys.exit("ERROR: reading {0}".format(story_manifest_file))
        story_files.append(story)

    # store an object with all stories and their data

    complete_stories = dict()
    for story in story_files:
        if verbose:
            print "processing story: {0}".format(story['name'])
        # Start building the story for the use case
        name = story['name']
        complete_stories[name] = {}
        complete_stories[name]['story_name'] = name
        complete_stories[name]['id'] = story['id']

        # grab modification date if it has one, otherwise write as creation date
        complete_stories[name]['creation_date'] = story['creation_date']
        if 'modification_date' in story:
            complete_stories[name]['modification_date'] = story['modification_date']

        else:
            complete_stories[name]['modification_date'] = story['creation_date']
        complete_stories[name]['description'] = story['description']
        if 'references' not in story:
            story['references'] = []
        complete_stories[name]['references'] = story['references']
        complete_stories[name]['version'] = story['version']
        complete_stories[name]['narrative'] = story['narrative']
        complete_stories[name]['spec_version'] = story['spec_version']
        complete_stories[name]['maintainers'] = story['maintainers']

        # grab searches
        if story['spec_version'] == 1:
            detections = []
            baselines = []
            investigations = []
            category = []

            category.append(story['category'])

            if 'detection_searches' in story['searches']:
                for d in story['searches']['detection_searches']:
                    detections.append({"type": "splunk", "name": d})
                complete_stories[name]['detections'] = detections

            # in spec v1 these are part of the story which is why we are grabbing them here
            if 'support_searches' in story['searches']:
                for b in story['searches']['support_searches']:
                    baselines.append({"type": "splunk", "name": b})
                complete_stories[name]['baselines'] = baselines

            if 'contextual_searches' in story['searches']:
                for i in story['searches']['contextual_searches']:
                    investigations.append({"type": "splunk", "name": i})
            if 'investigative_searches' in story['searches']:
                for i in story['searches']['investigative_searches']:
                    investigations.append({"type": "splunk", "name": i})
            complete_stories[name]['investigations'] = investigations

        if story['spec_version'] == 2:
            detections = []
            if 'detections' in story:
                for d in story['detections']:
                    detections.append({"type": d['type'], "name": d['name']})
            complete_stories[name]['detections'] = detections
            category = story['category']
        complete_stories[name]['category'] = category
    return complete_stories


def write_analytics_story_confv2(stories, detections, OUTPUT_DIR):
    # Create conf files from analytics stories files
    story_output_path = OUTPUT_DIR + "/default/analytics_stories_v2.conf"
    output_file = open(story_output_path, 'w')

    output_file.write("#############\n")
    output_file.write("# Automatically generated by generator.py in splunk/security-content\n")
    output_file.write("# On Date: {0} UTC\n".format(datetime.datetime.utcnow().replace(microsecond=0).isoformat()))
    output_file.write("# Author: Splunk Security Research\n")
    output_file.write("# Contact: research@splunk.com\n")
    output_file.write("#############\n\n")

    # Finish the story
    for story_name, story in sorted(stories.iteritems()):
        output_file.write("[%s]\n" % story_name)
        output_file.write("category = {0}\n".format(json.dumps(story['category']).strip('"')))
        output_file.write("creation_date = %s\n" % story['creation_date'])
        output_file.write("modification_date = %s\n" % story['modification_date'])
        output_file.write("id = %s\n" % story['id'])
        output_file.write("version = %s\n" % story['version'])
        output_file.write("reference = %s\n" % json.dumps(story['references']))

        if 'detections' in story:
            output_file.write("detections = %s\n" % json.dumps(story['detections']))

        # write all investigations
        total_investigations = []
        for d in story['detections']:
            if 'investigations' in detections[d['name']]:
                total_investigations.append(detections[d['name']]['investigations'])
        output_file.write("investigations = %s\n" % json.dumps(total_investigations[0]))

        # write all baselines
        total_baselines = []
        for d in story['detections']:
            if 'baselines' in detections[d['name']]:
                total_baselines.append(detections[d['name']]['baselines'])
        output_file.write("baselines = %s\n" % json.dumps(total_baselines[0]))

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


def write_analytics_story_confv1(stories, detections, investigations, baselines, OUTPUT_DIR):

    # Create conf files from analytics stories files
    story_output_path = OUTPUT_DIR + "/default/analytic_stories.conf"
    output_file = open(story_output_path, 'w')

    output_file.write("#############\n")
    output_file.write("# Automatically generated by generator.py in splunk/security-content\n")
    output_file.write("# On Date: {0} UTC\n".format(datetime.datetime.utcnow().replace(microsecond=0).isoformat()))
    output_file.write("# Author: Splunk Security Research\n")
    output_file.write("# Contact: research@splunk.com\n")
    output_file.write("#############\n\n")

    output_file.write("### STORIES ###\n\n")
    # Finish the story
    for story_name, story in sorted(stories.iteritems()):
        output_file.write("[%s]\n" % story_name)
        output_file.write("category = {0}\n".format(json.dumps(story['category'][0]).strip('"')))
        output_file.write("creation_date = %s\n" % story['creation_date'])
        output_file.write("modification_date = %s\n" % story['modification_date'])
        output_file.write("id = %s\n" % story['id'])
        output_file.write("version = %s\n" % story['version'])
        output_file.write("reference = %s\n" % json.dumps(story['references']))

        # write all detections
        if 'detections' in story:
            detection_searches = []
            for d in story['detections']:
                # we do not have any phantom or UBA detections for now we restrict this to Splunk
                if d['type'] == 'splunk':
                    detection_searches.append("ESCU - " + d['name'] + " - Rule")
            output_file.write("detection_searches = %s\n" % json.dumps(detection_searches))

        # grab mappings
        mappings = dict()

        # grab provising technologies
        providing_technologies = []

        # grab datamodels
        data_models = []

        # process the above for detections
        for detection_name, detection in sorted(detections.iteritems()):
            for s in detection['stories']:

                # check if the detection is part of this story
                if s == story_name:
                    # grab providing technologies
                    if 'providing_technologies' in detection:
                        for pt in detection['providing_technologies']:
                            providing_technologies.append(pt)

                    # grab data models
                    if 'data_models' in detection:
                        for dm in detection['data_models']:
                            data_models.append(dm)

                # we do not have any phantom or UBA detections for now we restrict this to Splunk
                if s == story_name and detection['type'] == 'splunk':
                    for key in detection['mappings'].keys():
                        mappings[key] = list(detection['mappings'][key])
        output_file.write("mappings = {0}\n".format(json.dumps(mappings)))

        # write all investigations
        total_investigations = []
        for investigation_name, investigation in sorted(investigations.iteritems()):
            for s in investigation['stories']:

                # check if the investigation is part of this story
                if s == story_name:
                    # grab providing technologies
                    if 'providing_technologies' in investigation:
                        for pt in investigation['providing_technologies']:
                            providing_technologies.append(pt)

                    # grab data models
                    if 'data_models' in investigation:
                        for dm in investigation['data_models']:
                            data_models.append(dm)

                # we do not write out searches for phantom in v1 spec, see write_analytics_story_confv2 for more details
                # for now we restrict it to splunk
                if s == story_name and investigation['type'] == 'splunk':
                    total_investigations.append("ESCU - " + investigation_name)
        output_file.write("investigative_searches = %s\n" % json.dumps(total_investigations))

        # write all baselines
        total_baselines = []
        for baseline_name, baseline in sorted(baselines.iteritems()):
            for s in baseline['stories']:

                # check if the baseline is part of this story
                if s == story_name:
                    # grab providing technologies
                    if 'providing_technologies' in baseline:
                        for pt in baseline['providing_technologies']:
                            providing_technologies.append(pt)

                    # grab data models
                    if 'data_models' in baseline:
                        for dm in baseline['data_models']:
                            data_models.append(dm)

                # we do not write out baselines for phantom and uba in v1 spec, see write_analytics_story_confv2
                # for now we restrict it to splunk
                if s == story_name and baseline['type'] == 'splunk':
                    total_baselines.append("ESCU - " + baseline_name)
        output_file.write("support_searches = %s\n" % json.dumps(total_baselines))

        # write out data models
        output_file.write("data_models = %s\n" % (json.dumps(sorted(set(data_models)))))

        # write out providing technologies models
        output_file.write("providing_technologies = %s\n" % (json.dumps(sorted(set(providing_technologies)))))

        # REMOVE THIS FUNCTION MAKE SURE ALL DESCRIPTIONs ARE NATIVELY IN MARKDOWN
        description = markdown(story['description'])
        output_file.write("description = %s\n" % description)

        # REMOVE THIS FUNCTION MAKE SURE ALL NARRATIVE ARE NATIVELY IN MARKDOWN
        if story['narrative']:
            narrative = markdown(story['narrative'])
            output_file.write("narrative = %s\n" % narrative)
        output_file.write("\n")

    output_file.write("#### END STORIES ####")
    # close file, count stories we found and return
    output_file.close()
    story_count = len(complete_stories.keys())
    return story_count, story_output_path


def write_use_case_lib_conf(stories, detections, investigations, baselines, OUTPUT_DIR):

    # Create conf files from analytics stories files
    use_case_lib_path = OUTPUT_DIR + "/default/use_case_library.conf"
    output_file = open(use_case_lib_path, 'w')
    output_file.write("#############\n")
    output_file.write("# Automatically generated by generator.py in splunk/security-content\n")
    output_file.write("# On Date: {0} UTC\n".format(datetime.datetime.utcnow().replace(microsecond=0).isoformat()))
    output_file.write("# Author: Splunk Security Research\n")
    output_file.write("# Contact: research@splunk.com\n")
    output_file.write("#############\n\n")
    output_file.write("### STORIES ###\n\n")
    # process the stories
    for story_name, story in sorted(stories.iteritems()):
        output_file.write("[analytic_story://%s]\n" % story_name)
        output_file.write("category = {0}\n".format(json.dumps(story['category'][0]).strip('"')))
        # output_file.write("created = %s\n" % story['creation_date'])
        output_file.write("last_updated = %s\n" % story['modification_date'])
        output_file.write("version = %s\n" % story['version'])
        output_file.write("references = %s\n" % json.dumps(story['references']))
        output_file.write("maintainers = %s\n" % json.dumps(story['maintainers']))
        output_file.write("spec_version = %s\n" % json.dumps(story['spec_version']))

        searches = []
        if 'detections' in story:
            for d in story['detections']:
                if d['type'] == 'splunk':
                    searches.append("ESCU - " + d['name'] + " - Rule")

        # write all investigations
        for investigation_name, investigation in sorted(investigations.iteritems()):
            for s in investigation['stories']:
                if s == story_name and investigation['type'] == 'splunk':
                    searches.append("ESCU - " + investigation_name)

        # write all baselines
        for baseline_name, baseline in sorted(baselines.iteritems()):
            for s in baseline['stories']:
                if s == story_name and baseline['type'] == 'splunk':
                    searches.append("ESCU - " + baseline_name)

        output_file.write("searches = %s\n" % json.dumps(searches))

        # REMOVE THIS FUNCTION MAKE SURE ALL DESCRIPTIONs ARE NATIVELY IN MARKDOWN
        description = markdown(story['description'])
        output_file.write("description = %s\n" % description)
        # REMOVE THIS FUNCTION MAKE SURE ALL NARRATIVE ARE NATIVELY IN MARKDOWN
        if story['narrative']:
            narrative = markdown(story['narrative'])
            output_file.write("narrative = %s\n" % narrative)
        output_file.write("\n")
    output_file.write("### END STORIES ###\n\n")

    output_file.write("### DETECTIONS ###\n\n")
    # process the detections
    for detection_name, detection in sorted(detections.iteritems()):
        output_file.write("[savedsearch://ESCU - {0} - Rule]\n".format(detection_name))
        output_file.write("type = detection\n")
        output_file.write("asset_type = {0}\n".format(detection['asset_type']))
        output_file.write("confidence = {0}\n".format(detection['confidence']))
        eli5 = markdown(detection['eli5'])
        output_file.write("explanation = {0}\n".format(eli5))
        how_to_implement = markdown(detection['how_to_implement'])
        output_file.write("how_to_implement = {0}\n".format(how_to_implement))
        output_file.write("annotations = {0}\n".format(json.dumps(detection['mappings'])))
        known_false_positives = markdown(detection['known_false_positives'])
        output_file.write("known_false_positives = {0}\n".format(known_false_positives))
        output_file.write("providing_technologies = {0}\n".format(json.dumps(detection['providing_technologies'])))
        output_file.write("\n")
    output_file.write("### END DETECTIONS ###\n\n")

    output_file.write("### INVESTIGATIONS ###\n\n")
    for investigation_name, investigation in sorted(investigations.iteritems()):
        output_file.write("[savedsearch://ESCU - {0}]\n".format(investigation_name))
        output_file.write("type = investigation\n")
        output_file.write("explanation = none\n")
        how_to_implement = markdown(investigation['how_to_implement'])
        output_file.write("how_to_implement = {0}\n".format(how_to_implement))
        known_false_positives = markdown(investigation['known_false_positives'])
        output_file.write("known_false_positives = {0}\n".format(known_false_positives))
        output_file.write("earliest_time_offset = {0}\n".format(investigation['earliest_time']))
        output_file.write("latest_time_offset = {0}\n".format(investigation['latest_time']))
        output_file.write("\n")
    output_file.write("### END INVESTIGATIONS ###\n\n")

    output_file.write("### BASELINES ###\n\n")
    for baseline_name, baseline in sorted(baselines.iteritems()):
        output_file.write("[savedsearch://ESCU - {0}]\n".format(baseline_name))
        output_file.write("type = support\n")
        eli5 = markdown(baseline['eli5'])
        output_file.write("explanation = {0}\n".format(eli5))
        how_to_implement = markdown(baseline['how_to_implement'])
        output_file.write("how_to_implement = {0}\n".format(how_to_implement))
        known_false_positives = markdown(baseline['known_false_positives'])
        output_file.write("known_false_positives = {0}\n".format(known_false_positives))
        output_file.write("providing_technologies = {0}\n".format(json.dumps(baseline['providing_technologies'])))
        output_file.write("\n")
    output_file.write("\n### END ESCU BASELINES ###\n\n")

    story_count = len(complete_stories.keys())
    return story_count, use_case_lib_path


def write_savedsearches_confv1(detections, investigations, baselines, OUTPUT_DIR):

    # Create savedsearches.conf for all our detections
    detections_output_path = OUTPUT_DIR + "/default/savedsearches.conf"
    output_file = open(detections_output_path, 'w')
    output_file.write("#############\n")
    output_file.write("# Automatically generated by generator.py in splunk/security-content\n")
    output_file.write("# On Date: {0} UTC\n".format(datetime.datetime.utcnow().replace(microsecond=0).isoformat()))
    output_file.write("# Author: Splunk Security Research\n")
    output_file.write("# Contact: research@splunk.com\n")
    output_file.write("#############\n\n")

    output_file.write("### ESCU DETECTIONS ###\n\n")
    # iterate through the detections and write them out
    for detection_name, detection in sorted(detections.iteritems()):
        # Write down the detection to file
        output_file.write("\n")
        output_file.write("[ESCU - {0} - Rule]\n".format(detection_name))
        output_file.write("action.escu = 0\n")
        output_file.write("action.escu.enabled = 1\n")
        description = markdown(detection['description'])
        output_file.write("description = {0}\n".format(description))
        output_file.write("action.escu.mappings = {0}\n".format(json.dumps(detection['mappings'])))
        if 'data_models' in detection:
            output_file.write("action.escu.data_models = {0}\n".format(json.dumps(detection['data_models'])))

        # NEED TO REMOVE MARKDOWN
        if 'eli5' in detection:
            eli5 = markdown(detection['eli5'])
            output_file.write("action.escu.eli5 = {0}\n".format(eli5))
        else:
            output_file.write("action.escu.eli5 = none\n")
        if 'how_to_implement' in detection:
            how_to_implement = markdown(detection['how_to_implement'])
            output_file.write("action.escu.how_to_implement = {0}\n".format(how_to_implement))
        else:
            output_file.write("action.escu.how_to_implement = none\n")
        if 'known_false_positives' in detection:
            known_false_positives = markdown(detection['known_false_positives'])
            output_file.write("action.escu.known_false_positives = %s\n" % known_false_positives)
        else:
            output_file.write("action.escu.known_false_positives = None at this time\n")

        output_file.write("action.escu.creation_date = {0}\n".format(detection['creation_date']))
        output_file.write("action.escu.modification_date = {0}\n".format(detection['modification_date']))
        output_file.write("action.escu.confidence = {0}\n".format(detection['confidence']))
        output_file.write("action.escu.full_search_name = ESCU - {0} - Rule\n".format(detection_name))
        output_file.write("action.escu.search_type = detection\n")

        if 'asset_type' in detection:
            output_file.write("action.escu.asset_at_risk = {0}\n".format(detection['asset_type']))
        if 'entities' in detection:
            output_file.write("action.escu.fields_required = {0}\n".format(json.dumps(detection['entities'])))
        if 'providing_technologies' in detection:
            output_file.write("action.escu.providing_technologies = {0}\n".format(json.dumps(detection['providing_technologies'])))
        output_file.write("action.escu.analytic_story = {0}\n".format(json.dumps(detection['stories'])))

        if 'cron' in detection:
            output_file.write("cron_schedule = {0}\n".format(detection['cron']))
        if 'earliest_time' in detection:
            output_file.write("dispatch.earliest_time = {0}\n".format(detection['earliest_time']))
        if 'latest_time' in detection:
            output_file.write("dispatch.latest_time = {0}\n".format(detection['latest_time']))

        # write correlation rule
        if 'correlation_rule' in detection:
            output_file.write("action.correlationsearch.enabled = 1\n")
            output_file.write("action.correlationsearch.label = {0}\n".format(detection_name))

            # write the notable event if it has one
            if 'notable' in detection['correlation_rule']:
                output_file.write("action.notable = 1\n")

            if 'nes_fields' in detection['correlation_rule']['notable']:
                output_file.write("action.notable.param.nes_fields = {0}\n"
                                  .format(detection['correlation_rule']['notable']['nes_fields']))
                output_file.write("action.notable.param.rule_description = {0}\n"
                                  .format(detection['correlation_rule']['notable']['rule_description']))
                output_file.write("action.notable.param.rule_title = {0}\n"
                                  .format(detection['correlation_rule']['notable']['rule_title']))
                output_file.write("action.notable.param.security_domain = {0}\n"
                                  .format(detection['security_domain']))
                output_file.write("action.notable.param.severity = {0}\n"
                                  .format(detection['confidence']))

            # include investigative search as a notable action
            # this is code that needs to be cleaned up on its implementation in ES
            investigations_output = ""
            has_phantom = False
            next_steps = ""
            for i in detection['investigations']:
                if i['type'] == 'splunk':
                    investigations_output += "ESCU - {0}\\n".format(i['name'])
                    next_steps = "{\"version\": 1, \"data\": \"Recommended following steps:\\n\\n1. \
                        [[action|escu_investigate]]: Based on ESCU investigate recommendations:\\n%s\"}" % investigations_output
                if i['type'] == 'phantom':
                    has_phantom = True

                    # lets pull the playbook URL out from investigation object
                    playbook_url = ''
                    for inv_name, inv in investigations.iteritems():
                        if i['name'] == inv_name:
                            playbook_url = inv['playbook_url']
                    # construct next steps with the playbook info
                    playbook_next_steps_string = "Splunk>Phantom Response Playbook - Monitor enrichment of the \
                        Splunk>Phantom Playbook called " + str(i['name']) + " and answer any \
                        analyst prompt in Mission Control with a response decision. \
                        Link to the playbook " + str(playbook_url)
                    next_steps = "{\"version\": 1, \"data\": \"Recommended following \
                        steps:\\n\\n1. [[action|runphantomplaybook]]: Phantom playbook \
                        recommendations:\\n%s\\n2. [[action|escu_investigate]]: \
                        Based on ESCU investigate recommendations:\\n%s\"}" % (playbook_next_steps_string,
                                                                               investigations_output)
            # update recommendation action if t here is a phantom one
            if has_phantom:
                output_file.write("action.notable.param.recommended_actions = runphantomplaybook, escu_investigate\n")
            else:
                output_file.write("action.notable.param.recommended_actions = escu_investigate\n")
            output_file.write("action.notable.param.next_steps = {0}\n".format(next_steps))

            if 'risk' in detection['correlation_rule']:
                output_file.write("action.risk = 1\n")
                output_file.write("action.risk.param._risk_object = {0}\n"
                                  .format(detection['correlation_rule']['risk']['risk_object']))
                output_file.write("action.risk.param._risk_object_type = {0}\n"
                                  .format(detection['correlation_rule']['risk']['risk_object_type'][0]))

                output_file.write("action.risk.param._risk_score = {0}\n"
                                  .format(detection['correlation_rule']['risk']['risk_score']))
                output_file.write("action.risk.param.verbose = 0\n")

            if 'suppress' in detection['correlation_rule']:
                output_file.write("alert.digest_mode = 1\n")
                output_file.write("alert.suppress = 1\n")
                output_file.write("alert.suppress.fields = {0}\n"
                                  .format(detection['correlation_rule']['suppress']['suppress_fields']))
                output_file.write("alert.suppress.period = {0}\n"
                                  .format(detection['correlation_rule']['suppress']['suppress_period']))

        output_file.write("action.escu.earliest_time_offset = 3600\n")
        output_file.write("action.escu.latest_time_offset = 86400\n")
        output_file.write("disabled=true\n")
        output_file.write("enableSched = 1\n")
        output_file.write("counttype = number of events\n")
        output_file.write("relation = greater than\n")
        output_file.write("quantity = 0\n")
        output_file.write("realtime_schedule = 0\n")
        output_file.write("schedule_window = auto\n")
        output_file.write("is_visible = false\n")
        output_file.write("search = {0}\n".format(detection['search']))
    output_file.write("\n### END ESCU DETECTIONS ###\n\n")

    # GENERATE INVESTIGATIVE SEARCH
    output_file.write("### ESCU INVESTIGATIONS ###\n")
    # iterate through the investigations and write them out
    for investigation_name, investigation in sorted(investigations.iteritems()):

        # skip phantom for now as we cannot use it on v1 app
        if investigation['type'] == 'phantom':
            continue

        # Write down the investigations to file
        output_file.write("\n")
        output_file.write("[ESCU - {0}]\n".format(investigation_name))
        output_file.write("action.escu = 0\n")
        output_file.write("action.escu.enabled = 1\n")
        output_file.write("action.escu.search_type = investigative\n")
        output_file.write("action.escu.full_search_name = ESCU - {0}\n".format(investigation_name))
        description = markdown(investigation['description'])
        output_file.write("description = {0}\n".format(description))
        output_file.write("action.escu.creation_date = {0}\n".format(investigation['creation_date']))
        output_file.write("action.escu.modification_date = {0}\n".format(investigation['modification_date']))
        output_file.write("action.escu.analytic_story = {0}\n".format(json.dumps(investigation['stories'])))
        output_file.write("action.escu.earliest_time_offset = 3600\n")
        output_file.write("action.escu.latest_time_offset = 86400\n")
        if 'data_models' in investigation:
            output_file.write("action.escu.data_models = {0}\n".format(json.dumps(investigation['data_models'])))
        if 'providing_technologies' in detection:
            output_file.write("action.escu.providing_technologies = {0}\n".format(
                json.dumps(investigation['providing_technologies'])))
        # NEED TO REMOVE MARKDOWN FUNCTION
        if 'eli5' in investigation:
            eli5 = markdown(investigation['eli5'])
            output_file.write("action.escu.eli5 = {0}\n".format(eli5))
        else:
            output_file.write("action.escu.eli5 = none\n")
        if 'how_to_implement' in investigation:
            how_to_implement = markdown(investigation['how_to_implement'])
            output_file.write("action.escu.how_to_implement = {0}\n".format(how_to_implement))
        else:
            output_file.write("action.escu.how_to_implement = none\n")
        if 'known_false_positives' in investigation:
            known_false_positives = markdown(investigation['known_false_positives'])
            output_file.write("action.escu.known_false_positives = %s\n" % known_false_positives)
        else:
            output_file.write("action.escu.known_false_positives = None at this time\n")
        if 'entities' in investigation:
            output_file.write("action.escu.fields_required = {0}\n".format(json.dumps(investigation['entities'])))
        output_file.write("disabled=true\n")
        output_file.write("schedule_window = auto\n")
        output_file.write("is_visible = false\n")
        output_file.write("search = {0}\n".format(investigation['search']))
    output_file.write("\n### END ESCU INVESTIGATIONS ###\n\n")

    # GENERATE BASELINES
    output_file.write("### ESCU BASELINES ###\n")
    # iterate through the baselines and write them out
    for baseline_name, baseline in sorted(baselines.iteritems()):
        # Write down the baseline to file
        output_file.write("\n")
        output_file.write("[ESCU - {0}]\n".format(baseline_name))
        output_file.write("action.escu = 0\n")
        output_file.write("action.escu.enabled = 1\n")
        output_file.write("action.escu.search_type = support\n")
        output_file.write("action.escu.full_search_name = ESCU - {0}\n".format(baseline_name))
        description = markdown(baseline['description'])
        output_file.write("description = {0}\n".format(description))
        output_file.write("action.escu.creation_date = {0}\n".format(baseline['creation_date']))
        output_file.write("action.escu.modification_date = {0}\n".format(baseline['modification_date']))
        output_file.write("action.escu.analytic_story = {0}\n".format(json.dumps(baseline['stories'])))
        if 'data_models' in baseline:
            output_file.write("action.escu.data_models = {0}\n".format(json.dumps(baseline['data_models'])))
        if 'earliest_time' in baseline:
            output_file.write("dispatch.earliest_time = {0}\n".format(baseline['earliest_time']))
        if 'latest_time' in baseline:
            output_file.write("dispatch.latest_time = {0}\n".format(baseline['latest_time']))
        if 'providing_technologies' in baseline:
            output_file.write("action.escu.providing_technologies = {0}\n".format(json.dumps(baseline['providing_technologies'])))
        # NEED TO REMOVE MARKDOWN FUNCTION
        if 'eli5' in baseline:
            eli5 = markdown(baseline['eli5'])
            output_file.write("action.escu.eli5 = {0}\n".format(eli5))
        else:
            output_file.write("action.escu.eli5 = none\n")
        if 'how_to_implement' in baseline:
            how_to_implement = markdown(baseline['how_to_implement'])
            output_file.write("action.escu.how_to_implement = {0}\n".format(how_to_implement))
        else:
            output_file.write("action.escu.how_to_implement = none\n")
        if 'known_false_positives' in baseline:
            known_false_positives = markdown(baseline['known_false_positives'])
            output_file.write("action.escu.known_false_positives = %s\n" % known_false_positives)
        else:
            output_file.write("action.escu.known_false_positives = None at this time\n")
        if 'entities' in baseline:
            output_file.write("action.escu.fields_required = {0}\n".format(json.dumps(baseline['entities'])))
        output_file.write("disabled=true\n")
        output_file.write("schedule_window = auto\n")
        output_file.write("is_visible = false\n")
        output_file.write("search = {0}\n".format(baseline['search']))
    output_file.write("\n### END ESCU BASELINES ###\n\n")
    output_file.write("\n### USAGE DASHBOARD CONFIGURATIONS ###\n\n")

    usconf = open('bin/usage_searches.conf', 'r')
    usage_searches = usconf.read()
    usconf.close()
    output_file.write(usage_searches)
    output_file.write("\n\n### END OF USAGE DASHBOARD CONFIGURATIONS ###")

    output_file.close()

    detections_count = len(detections)
    investigations_count = len(investigations)
    baselines_count = len(baselines)
    detection_path = detections_output_path

    return detections_count, investigations_count, baselines_count, detection_path


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="generates splunk conf files out of security-content manifests", epilog="""
    This tool converts manifests to the source files to be used by products like Splunk Enterprise.
    It generates the savesearches.conf, analytics_stories.conf files for ES.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    parser.add_argument("-sv1", "--storiesv1", required=False, default=True, action='store_true',
                        help="generates analytics_stories.conf in v1 format")
    parser.add_argument("-u", "--use_case_lib", required=False, default=True, action='store_true',
                        help="generates use_case_library.conf for ES")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_DIR = args.output
    verbose = args.verbose
    storiesv1 = args.storiesv1
    use_case_lib = args.use_case_lib

    complete_stories = generate_stories(REPO_PATH, verbose)
    complete_detections = generate_detections(REPO_PATH, complete_stories)
    complete_investigations = generate_investigations(REPO_PATH, complete_detections, complete_stories)
    complete_baselines = generate_baselines(REPO_PATH, complete_detections, complete_stories)
    # complete_responses = generate_responses(REPO_PATH, complete_responses)

    if storiesv1:
        story_count, story_path = write_analytics_story_confv1(complete_stories, complete_detections,
                                                               complete_investigations, complete_baselines, OUTPUT_DIR)
        print "{0} stories have been successfully written to {1}".format(story_count, story_path)
    else:
        story_count, story_path = write_analytics_story_confv2(complete_stories, complete_detections,
                                                               complete_investigations, complete_baselines, OUTPUT_DIR)
        print "{0} stories have been successfully written to {1}".format(story_count, story_path)

    if use_case_lib:
        story_count, use_case_lib_path = write_use_case_lib_conf(complete_stories,
                                                                 complete_detections, complete_investigations,
                                                                 complete_baselines, OUTPUT_DIR)
        print "{0} stories have been successfully to {1}".format(story_count, use_case_lib_path)

    detections_count, investigations_count, baselines_count, detection_path = \
        write_savedsearches_confv1(complete_detections, complete_investigations,
                                   complete_baselines, OUTPUT_DIR)
    print "{0} detections have been successfully written to {1}\n" \
          "{2} investigations have been successfully written to {1}\n" \
          "{3} baselines have been successfully written to {1}".format(detections_count, detection_path,
                                                                       investigations_count, baselines_count)

    print "security content generation completed.."
