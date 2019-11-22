#!/usr/bin/python

'''
Generates splunk configurations from manifest files under the security-content repo.
'''

import glob
import yaml
import argparse
from os import path
import sys
import datetime
from jinja2 import Environment, FileSystemLoader

# global variables
REPO_PATH = ''
VERBOSE = False
OUTPUT_PATH = ''


def load_objects(file_path):
    files = []
    manifest_files = path.join(path.expanduser(REPO_PATH), file_path)

    for file in glob.glob(manifest_files):
        files.append(load_file(file))

    return files


def load_file(file_path):
    with open(file_path, 'r') as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def generate_transforms_conf(lookups):
    sorted_lookups = sorted(lookups, key=lambda i: i['name'])

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('transforms.j2')
    output_path = OUTPUT_PATH + "/default/transforms.conf"
    output = template.render(lookups=sorted_lookups, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)

    return output_path


def generate_savedsearches_conf(detections, investigations, baselines):

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('savedsearches.j2')
    output_path = OUTPUT_PATH + "/default/savedsearches.conf"
    output = template.render(detections=detections, investigations=investigations, baselines=baselines, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)

    return output_path


def generate_analytics_story_conf(stories):

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('analytic_stories.j2')
    output_path = OUTPUT_PATH + "/default/analytic_stories.conf"
    output = template.render(stories=stories, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)

    return output_path


def generate_use_case_library_conf(stories, detections, investigations, baselines):

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('use_case_library.j2')
    output_path = OUTPUT_PATH + "/default/use_case_library.conf"
    output = template.render(stories=stories, detections=detections,
                             investigations=investigations,
                             baselines=baselines, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)

    return output_path


def generate_macros_conf(macros):

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('macros.j2')
    output_path = OUTPUT_PATH + "/default/macros.conf"
    output = template.render(macros=macros, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)

    return output_path


def identify_next_steps(detections, investigations):
    enriched_detections = []
    for detection in detections:
        if 'splunk' in detection['detect']:
            if 'correlation_rule' in detection['detect']['splunk']:
                investigations_output = ""
                has_phantom = False
                next_steps = ""
                for i in detection['investigations']:
                    if i['type'] == 'splunk':
                        investigations_output += "ESCU - {0}\\n".format(i['name'])
                        next_steps = "{\"version\": 1, \"data\": \"Recommended following steps:\\n\\n"
                        next_steps += "1.[[action|escu_investigate]]: Based on ESCU investigate \
                                        recommendations:\\          n%s\"}" % investigations_output
                    if i['type'] == 'phantom':
                        has_phantom = True

                        # lets pull the playbook URL out from investigation object
                        playbook_url = ''
                        for inv in investigations:
                            if i['name'] == inv['name']:
                                playbook_url = inv['investigate']['phantom']['playbook_url']
                        # construct next steps with the playbook info
                        playbook_next_steps_string = "Splunk>Phantom Response Playbook - Monitor enrichment of the \
                            Splunk>Phantom Playbook called " + str(i['name']) + " and answer any \
                            analyst prompt in Mission Control with a response decision. \
                            Link to the playbook " + str(playbook_url)
                        next_steps = "{\"version\": 1, \"data\": \"Recommended following"
                        next_steps += ":\\n\\n1. [[action|runphantomplaybook]]: Phantom playbook "
                        next_steps += "recommendations:\\n%s\\n2. [[action|escu_investigate]]: " % (playbook_next_steps_string)
                        next_steps += "Based on ESCU investigate recommendations:\\n%s\"}" % (investigations_output)
                if has_phantom:
                    detection['recommended_actions'] = 'runphantomplaybook, escu_investigate'
                else:
                    detection['recommended_actions'] = 'escu_investigate'
                detection['next_steps'] = next_steps

        enriched_detections.append(detection)

    return enriched_detections


def map_investigations_to_detection(detections):
    inv_det = {}
    for detection in detections:
        if 'investigations' in detection:
            for investigation in detection['investigations']:
                if not (investigation['id'] in inv_det):
                    inv_det[investigation['id']] = {detection['id']}
                else:
                    inv_det[investigation['id']].add(detection['id'])
    return inv_det


def map_baselines_to_detection(detections):
    bas_det = {}
    for detection in detections:
        if 'baselines' in detection:
            for baseline in detection['baselines']:
                if not (baseline['id'] in bas_det):
                    bas_det[baseline['id']] = {detection['id']}
                else:
                    bas_det[baseline['id']].add(detection['id'])
    return bas_det


def map_detection_to_stories(stories):
    det_sto = {}
    for story in stories:
        for detection in story['detections']:
            if not (detection['detection_id'] in det_sto):
                det_sto[detection['detection_id']] = {story['name']}
            else:
                det_sto[detection['detection_id']].add(story['name'])
    return det_sto


def enrich_investigations_with_stories(investigations, map_inv_det, map_det_sto):
    enriched_investigations = []
    for investigation in investigations:
        stories_set = set()
        if investigation['id'] in map_inv_det:
            for detection_id in map_inv_det[investigation['id']]:
                if detection_id in map_det_sto:
                    stories_set = stories_set | map_det_sto[detection_id]

        investigation['stories'] = sorted(list(stories_set))
        enriched_investigations.append(investigation)
    return enriched_investigations


def enrich_detections_with_stories(detections, map_det_sto):
    enriched_detections = []
    for detection in detections:
        stories_set = set()
        if detection['id'] in map_det_sto:
            stories_set = stories_set | map_det_sto[detection['id']]
        detection['stories'] = sorted(list(stories_set))
        enriched_detections.append(detection)
    return enriched_detections


def enrich_baselines_with_stories(baselines, map_bas_det, map_det_sto):
    enriched_baselines = []
    for baseline in baselines:
        stories_set = set()
        if baseline['id'] in map_bas_det:
            for baseline_id in map_bas_det[baseline['id']]:
                if baseline_id in map_det_sto:
                    stories_set = stories_set | map_det_sto[baseline_id]

        baseline['stories'] = sorted(list(stories_set))
        enriched_baselines.append(baseline)
    return enriched_baselines


def enrich_stories(stories, detections, investigations, baselines):
    enriched_stories = []
    for story in stories:
        providing_technologies = set()
        data_models = set()
        detection_names = []
        mappings = dict()
        mappings["cis20"] = set()
        mappings["kill_chain_phases"] = set()
        mappings["mitre_attack"] = set()
        mappings["nist"] = set()
        searches = []

        for detection in story['detections']:
            for detection_obj in detections:
                if detection['detection_id'] == detection_obj['id']:
                    if 'providing_technologies' in detection_obj['data_metadata']:
                        providing_technologies = providing_technologies | set(detection_obj
                                                                              ['data_metadata']['providing_technologies'])
                    if 'data_models' in detection_obj['data_metadata']:
                        data_models = data_models | set(detection_obj['data_metadata']['data_models'])
                    if detection_obj['type'] == 'splunk':
                        detection_names.append("ESCU - " + detection_obj['name'] + " - Rule")

                    for key in detection_obj['mappings']:
                        mappings[key] = mappings[key] | set(detection_obj['mappings'][key])

        for key in mappings.keys():
            mappings[key] = sorted(list(mappings[key]))

        story['mappings'] = mappings
        story['detection_names'] = sorted(detection_names)
        searches = sorted(detection_names)

        investigation_names = []

        for investigation in investigations:
            for s in investigation['stories']:
                if s == story['name']:
                    if 'providing_technologies' in investigation['data_metadata']:
                        providing_technologies = providing_technologies | set(investigation
                                                                              ['data_metadata']['providing_technologies'])
                    if 'data_models' in investigation['data_metadata']:
                        data_models = data_models | set(investigation['data_metadata']['data_models'])
                    if investigation['type'] == 'splunk':
                        investigation_names.append("ESCU - " + investigation['name'])

        story['investigation_names'] = sorted(investigation_names)
        searches = searches + sorted(investigation_names)

        baseline_names = []

        for baseline in baselines:
            for s in baseline['stories']:
                if s == story['name']:
                    if 'providing_technologies' in baseline['data_metadata']:
                        providing_technologies = providing_technologies | set(baseline['data_metadata']['providing_technologies'])
                    if 'data_models' in baseline['data_metadata']:
                        data_models = data_models | set(baseline['data_metadata']['data_models'])
                    if baseline['type'] == 'splunk':
                        baseline_names.append("ESCU - " + baseline['name'])

        story['baseline_names'] = sorted(baseline_names)
        searches = searches + sorted(baseline_names)

        story['providing_technologies'] = sorted(list(providing_technologies))
        story['data_models'] = sorted(list(data_models))
        story['searches'] = searches

        enriched_stories.append(story)

    return enriched_stories


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="generates splunk conf files out of security-content manifests", epilog="""
    This tool converts manifests to the source files to be used by products like Splunk Enterprise.
    It generates the savesearches.conf, analytics_stories.conf files for ES.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_PATH = args.output
    VERBOSE = args.verbose

    stories = load_objects("stories/*.yml")
    macros = load_objects("macros/*.yml")
    lookups = load_objects("lookups/*.yml")
    detections = load_objects("detections/*.yml")
    investigations = load_objects("investigations/*.yml")
    baselines = load_objects("baselines/*.yml")

    detections = identify_next_steps(detections, investigations)

    map_inv_det = map_investigations_to_detection(detections)
    map_det_sto = map_detection_to_stories(stories)
    map_bas_det = map_baselines_to_detection(detections)
    detections = enrich_detections_with_stories(detections, map_det_sto)
    investigations = enrich_investigations_with_stories(investigations, map_inv_det, map_det_sto)
    baselines = enrich_baselines_with_stories(baselines, map_bas_det, map_det_sto)
    stories = enrich_stories(stories, detections, investigations, baselines)

    lookups_path = generate_transforms_conf(lookups)

    detections = sorted(detections, key=lambda d: d['name'])
    investigations = sorted(investigations, key=lambda i: i['name'])
    baselines = sorted(baselines, key=lambda b: b['name'])
    detection_path = generate_savedsearches_conf(detections, investigations, baselines)

    stories = sorted(stories, key=lambda s: s['name'])
    story_path = generate_analytics_story_conf(stories)

    use_case_lib_path = generate_use_case_library_conf(stories, detections, investigations, baselines)

    macros = sorted(macros, key=lambda m: m['name'])
    macros_path = generate_macros_conf(macros)

    if VERBOSE:
        print("{0} stories have been successfully written to {1}".format(len(stories), story_path))
        print("{0} stories have been successfully written to {1}".format(len(stories), use_case_lib_path))
        print("{0} detections have been successfully written to {1}".format(len(detections), detection_path))
        print("{0} investigations have been successfully written to {1}".format(len(investigations), detection_path))
        print("{0} baselines have been successfully written to {1}".format(len(baselines), detection_path))
        print("{0} macros have been successfully written to {1}".format(len(macros), macros_path))
        print("security content generation completed..")
