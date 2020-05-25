import os
import sys
import yaml
import glob
import re

from collections import OrderedDict
from attackcti import attack_client


lift = attack_client()
all_enterprise = lift.get_enterprise(stix_format=False)

def represent_ordereddict(dumper, data):
    value = []

    for item_key, item_value in data.items():
        node_key = dumper.represent_data(item_key)
        node_value = dumper.represent_data(item_value)

        value.append((node_key, node_value))

    return yaml.nodes.MappingNode(u'tag:yaml.org,2002:map', value)


def attack_lookup_id(inputs_array):
    outputs = []
    for input in inputs_array:
        for technique in all_enterprise['techniques']:
            if technique['technique'].lower()==input.lower():
                outputs.append(technique['external_references'][0]['external_id'])

    return outputs


def remove_special_characters(input_str):
    output_str = input_str.replace('.',' ').replace('/',' ').replace('(',' ').replace(')',' ').replace('&','and').replace('_',' ')
    return output_str

def generate_content():
    ## detections ##
    detection_files = glob.glob("../security-content-tmp/detections/*.yml")
    story_files = glob.glob("../security-content-tmp/stories/*.yml")
    old_detections = []
    old_stories = []
    for detection_file in detection_files:
        old_detections.append(load_file(detection_file))

    for story_file in story_files:
        old_stories.append(load_file(story_file))

    det_sto = map_detection_to_stories(old_stories)

    print('## Detections ##')
    for orig_dict in old_detections:
        print(orig_dict['name'])
        new_dict = {}
        new_dict['name'] = remove_special_characters(orig_dict['name'])
        new_dict['id'] = orig_dict['id']
        new_dict['version'] = int(float(orig_dict['version']))
        if 'modification_date' in orig_dict:
            new_dict['date'] = orig_dict['modification_date']
        else:
            new_dict['date'] = orig_dict['creation_date']
        new_dict['description'] = orig_dict['description']
        new_dict['how_to_implement'] = orig_dict['how_to_implement']
        new_dict['type'] = 'ESCU'
        if 'references' in orig_dict:
            new_dict['references'] = orig_dict['references']
        for author in orig_dict['original_authors']:
            author_str = author['name'] + ', ' + author['company'] + ', '
        new_dict['author'] = author_str[:-2]
        if 'splunk' in orig_dict['detect']:
            new_dict['search'] = orig_dict['detect']['splunk']['correlation_rule']['search']
        elif 'uba' in orig_dict['detect']:
            new_dict['search'] = orig_dict['detect']['uba']['correlation_rule']['search']

        if not str('_filter') in new_dict['search']:
            new_dict['search'] = new_dict['search'] + ' | `' + new_dict['name'].replace('-','_').replace(' ','_').lower() + '_filter`'

        if 'search' in new_dict:
            new_dict['search'] = check_source_macro(new_dict['search'])
            new_dict['search'] = change_filter_macro(new_dict)

        new_dict['known_false_positives'] = orig_dict['known_false_positives']
        tag_dict = {}
        if orig_dict['id'] in det_sto:
            tag_dict['analytics_story'] = list(det_sto[orig_dict['id']])
        if 'mitre_attack' in orig_dict['mappings']:
            mitre_attack_id = attack_lookup_id(orig_dict['mappings']['mitre_attack'])
            if len(mitre_attack_id)>0:
                tag_dict['mitre_attack_id'] = attack_lookup_id(orig_dict['mappings']['mitre_attack'])
        if 'kill_chain_phases' in orig_dict['mappings']:
            tag_dict['kill_chain_phases'] = orig_dict['mappings']['kill_chain_phases']
        if 'cis20' in orig_dict['mappings']:
            tag_dict['cis20'] = orig_dict['mappings']['cis20']
        if 'nist' in orig_dict['mappings']:
            tag_dict['nist'] = orig_dict['mappings']['nist']
        if 'security_domain' in orig_dict:
            tag_dict['security_domain'] = orig_dict['security_domain']
        if 'asset_type' in orig_dict:
            tag_dict['asset_type'] = orig_dict['asset_type']
        new_dict['tags'] = tag_dict
        ordered_new_dict = OrderedDict(new_dict.items())
        new_file_name = new_dict['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
        with open('detections/' + new_file_name + '.yml', 'w+' ) as outfile:
	           yaml.dump( new_dict , outfile , default_flow_style=False, sort_keys=False)


    ## baselines ##
    baseline_files = glob.glob("../security-content-tmp/baselines/*.yml")
    old_baselines = []
    for baseline_file in baseline_files:
        old_baselines.append(load_file(baseline_file))

    bas_det = map_baselines_to_detection(old_detections)
    old_baselines = enrich_baselines_with_stories(old_baselines, bas_det, det_sto)
    bas_det_name = map_baselines_to_detection_names(old_detections)

    print()
    print('## Baselines ##')
    for orig_dict in old_baselines:
        print(orig_dict['name'])
        new_dict = {}
        new_dict['name'] = remove_special_characters(orig_dict['name'])
        new_dict['id'] = orig_dict['id']
        new_dict['version'] = int(float(orig_dict['version']))
        if 'modification_date' in orig_dict:
            new_dict['date'] = orig_dict['modification_date']
        else:
            new_dict['date'] = orig_dict['creation_date']
        new_dict['description'] = orig_dict['description']
        new_dict['how_to_implement'] = orig_dict['how_to_implement']
        for author in orig_dict['original_authors']:
            author_str = author['name'] + ', ' + author['company'] + ', '
        new_dict['author'] = author_str[:-2]
        new_dict['search'] = orig_dict['baseline']['splunk']['search']

        new_dict['search'] = check_source_macro(new_dict['search'])

        tag_dict = {}
        if len(orig_dict['stories']) > 0:
            tag_dict['analytics_story'] = list(orig_dict['stories'])
        if orig_dict['id'] in bas_det_name:
            tag_dict['detections'] = list(bas_det_name[orig_dict['id']])
        new_dict['tags'] = tag_dict
        ordered_new_dict = OrderedDict(new_dict.items())
        new_file_name = new_dict['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
        with open('baselines/' + new_file_name + '.yml', 'w+' ) as outfile:
	           yaml.dump( new_dict , outfile , default_flow_style=False, sort_keys=False)


    ## stories ##
    story_files = glob.glob("../security-content-tmp/stories/*.yml")
    old_stories = []
    for story_file in story_files:
        old_stories.append(load_file(story_file))

    print()
    print('## Stories ##')
    for orig_dict in old_stories:
        print(orig_dict['name'])
        new_dict = {}
        new_dict['name'] = remove_special_characters(orig_dict['name'])
        new_dict['id'] = orig_dict['id']
        new_dict['version'] = int(float(orig_dict['version']))
        if 'modification_date' in orig_dict:
            new_dict['date'] = orig_dict['modification_date']
        else:
            new_dict['date'] = orig_dict['creation_date']
        new_dict['description'] = orig_dict['description']
        new_dict['narrative'] = orig_dict['narrative']
        for author in orig_dict['original_authors']:
            author_str = author['name'] + ', ' + author['company'] + ', '
        new_dict['author'] = author_str[:-2]
        new_dict['type'] = 'ESCU'
        if 'references' in orig_dict:
            new_dict['references'] = orig_dict['references']
        tag_dict = {}
        tag_dict['analytics_story'] = remove_special_characters(orig_dict['name'])
        tag_dict['usecase'] = orig_dict['usecase']
        tag_dict['category'] = orig_dict['category']
        new_dict['tags'] = tag_dict
        ordered_new_dict = OrderedDict(new_dict.items())
        new_file_name = new_dict['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
        with open('stories/' + new_file_name + '.yml', 'w+' ) as outfile:
	           yaml.dump( new_dict , outfile , default_flow_style=False, sort_keys=False)


    ## response tasks ##
    investigation_files = glob.glob("../security-content-tmp/investigations/*.yml")
    old_investigations = []
    for investigation_file in investigation_files:
        old_investigations.append(load_file(investigation_file))

    map_inv_det = map_investigations_to_detection(old_detections)

    print()
    print('## Response Tasks ##')
    for orig_dict in old_investigations:
        print(orig_dict['name'])
        new_dict = {}
        new_dict['name'] = remove_special_characters(orig_dict['name'])
        new_dict['id'] = orig_dict['id']
        new_dict['version'] = int(float(orig_dict['version']))
        if 'modification_date' in orig_dict:
            new_dict['date'] = orig_dict['modification_date']
        else:
            new_dict['date'] = orig_dict['creation_date']
        new_dict['description'] = orig_dict['description']
        new_dict['how_to_implement'] = orig_dict['how_to_implement']
        for author in orig_dict['original_authors']:
            author_str = author['name'] + ', ' + author['company'] + ', '
        new_dict['author'] = author_str[:-2]
        if 'splunk' in orig_dict['investigate']:
            new_dict['inputs'] = orig_dict['investigate']['splunk']['fields_required']
            new_dict['search'] = orig_dict['investigate']['splunk']['search']
            new_dict = change_response_task_variable(new_dict)
        # elif 'phantom' in orig_dict['investigate']:
        #     phantom_dict = {}
        #     phantom_dict['name'] = orig_dict['investigate']['phantom']['playbook_name']
        #     phantom_dict['url_json'] = 'todo'
        #     phantom_dict['url_py'] = 'todo'
        #     new_dict['playbook'] = phantom_dict
        else:
            continue
        stories = get_stories_for_investigations(map_inv_det, det_sto, orig_dict)
        if len(stories) > 0:
            tag_dict = {}
            tag_dict['analytics_story'] = stories
            new_dict['tags'] = tag_dict
        ordered_new_dict = OrderedDict(new_dict.items())
        new_file_name = new_dict['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
        with open('response_tasks/' + new_file_name + '.yml', 'w+' ) as outfile:
	           yaml.dump( new_dict , outfile , default_flow_style=False, sort_keys=False)



def load_file(file_path):
    with open(file_path, 'r') as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file

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

def map_detection_to_stories(stories):
    det_sto = {}
    for story in stories:
        if 'detections' in story:
            for detection in story['detections']:
                if not (detection['detection_id'] in det_sto):
                    det_sto[detection['detection_id']] = {remove_special_characters(story['name'])}
                else:
                    det_sto[detection['detection_id']].add(remove_special_characters(story['name']))
    return det_sto

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

def map_baselines_to_detection_names(detections):
    bas_det = {}
    for detection in detections:
        if 'baselines' in detection:
            for baseline in detection['baselines']:
                if not (baseline['id'] in bas_det):
                    bas_det[baseline['id']] = {detection['name']}
                else:
                    bas_det[baseline['id']].add(detection['name'])
    return bas_det

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


def get_stories_for_investigations(map_inv_det, map_det_sto, investigation):
    story_names = set()
    if investigation['id'] in map_inv_det:
        detections = map_inv_det[investigation['id']]
        for detection in detections:
            if detection in map_det_sto:
                stories = map_det_sto[detection]
                story_names = story_names | stories

    return sorted(list(story_names))


def check_source_macro(search):
    new_search = search

    mappings = {"aws:cloudtrail": "cloudtrail",
                "netbackup_logs": "netbackup",
                "okta_log": "okta",
                "stream:http": "stream_http",
                "google:gcp:pubsub:message": "google_gcp_pubsub_message",
                "aws:s3:accesslogs": "aws_s3_accesslogs",
                "aws:cloudwatchlogs:eks": "aws_cloudwatchlogs_eks",
                "wineventlog_security": "wineventlog_security",
                "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational": "sysmon",
                "wineventlog:microsoft-windows-wmi-activity/operational": "wmi",
                "wineventlog_system": "wineventlog_system",
                "aws:cloudwatchlogs:vpcflow": "cloudwatchlogs_vpcflow"}

    adjust_position = 0
    for match in re.finditer('(sourcetype\s?|index\s?|source\s?|eventtype\s?)=\s?([^\s)]*)',search):
        if not match.group()=="source=pods" and not match.group()=="index=_internal" and not match.group()=="sourcetype=splunkd_ui_access" and not match.group()=="sourcetype=splunk_web_access":
            content_match = match.group(2)
            if content_match.startswith('"'):
                content_match = content_match[1:]
            if content_match.endswith('"'):
                content_match = content_match[:-1]

            new_search = new_search[0: (match.start() - adjust_position):] + new_search[(match.end() - adjust_position) + 1::]
            new_search = new_search[:(match.start() - adjust_position)] + '`' + mappings[content_match] + '` ' + new_search[(match.start() - adjust_position):]
            adjust_position = match.end() - match.start() - len(mappings[content_match]) - 2

            #generate macro configuration

            new_dict = {}
            new_dict['definition'] = match.group()
            new_dict['description'] = 'customer specific splunk configurations(eg- index, source, sourcetype). Replace the macro definition with configurations for your Splunk Environmnent.'
            new_dict['name'] = mappings[content_match]
            ordered_new_dict = OrderedDict(new_dict.items())
            new_file_name = mappings[content_match]
            with open('macros/' + new_file_name + '.yml', 'w+' ) as outfile:
    	           yaml.dump( new_dict , outfile , default_flow_style=False, sort_keys=False)

    return new_search


def change_filter_macro(object):
    new_search = object['search']
    filter_macro = re.search("([a-z0-9_]*_filter)", new_search)
    if filter_macro.group(1) != (object['name'].replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter'):
        for match in re.finditer("([a-z0-9_]*_filter)", new_search):
            new_search = new_search[0: match.start() - 1:] + new_search[match.end() + 1::]
            new_search = new_search[:match.start() - 1] + '`' + object['name'].replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter' + '` ' + new_search[match.start():]

    return new_search


def change_response_task_variable(object):
    if 'inputs' in object:
        for input in object['inputs']:
            if 'search' in object:
                new_search = object['search'].replace("{" + input + "}", "$" + input + "$")
                object['search'] = new_search
    return object


if __name__ == "__main__":
    generate_content()
