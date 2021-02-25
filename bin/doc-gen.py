import glob
import yaml
import argparse
from os import path
import sys
import re
from jinja2 import Environment, FileSystemLoader


def load_objects(file_path):
    files = []
    manifest_files = path.join(path.expanduser(REPO_PATH), file_path)

    for file in sorted(glob.glob(manifest_files)):
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


def prepare_content(stories, detections):

    # enrich stories with information from detections: data_models, mitre_ids, kill_chain_phases, nists
    sto_to_data_models = {}
    sto_to_mitre_attack_ids = {}
    sto_to_kill_chain_phases = {}
    sto_to_ciss = {}
    sto_to_nists = {}
    sto_to_det = {}
    for detection in detections:
        if 'analytic_story' in detection['tags']:
            for story in detection['tags']['analytic_story']:
                if story in sto_to_det.keys():
                    sto_to_det[story].add(detection['name'])
                else:
                    sto_to_det[story] = {detection['name']}

                data_model = parse_data_models_from_search(detection['search'])
                if data_model:
                    if story in sto_to_data_models.keys():
                        sto_to_data_models[story].add(data_model)
                    else:
                        sto_to_data_models[story] = {data_model}

                if 'mitre_attack_id' in detection['tags']:
                    if story in sto_to_mitre_attack_ids.keys():
                        for mitre_attack_id in detection['tags']['mitre_attack_id']:
                            sto_to_mitre_attack_ids[story].add(mitre_attack_id)
                    else:
                        sto_to_mitre_attack_ids[story] = set(detection['tags']['mitre_attack_id'])

                if 'kill_chain_phases' in detection['tags']:
                    if story in sto_to_kill_chain_phases.keys():
                        for kill_chain in detection['tags']['kill_chain_phases']:
                            sto_to_kill_chain_phases[story].add(kill_chain)
                    else:
                        sto_to_kill_chain_phases[story] = set(detection['tags']['kill_chain_phases'])

                if 'cis20' in detection['tags']:
                    if story in sto_to_ciss.keys():
                        for cis in detection['tags']['cis20']:
                            sto_to_ciss[story].add(cis)
                    else:
                        sto_to_ciss[story] = set(detection['tags']['cis20'])

                if 'nist' in detection['tags']:
                    if story in sto_to_nists.keys():
                        for nist in detection['tags']['nist']:
                            sto_to_nists[story].add(nist)
                    else:
                        sto_to_nists[story] = set(detection['tags']['nist'])

    for story in stories:
        story['detections'] = sorted(sto_to_det[story['name']])
        if story['name'] in sto_to_data_models:
            story['data_models'] = sorted(sto_to_data_models[story['name']])
        if story['name'] in sto_to_mitre_attack_ids:
            story['mitre_attack_ids'] = sorted(sto_to_mitre_attack_ids[story['name']])
        if story['name'] in sto_to_kill_chain_phases:
            story['kill_chain_phases'] = sorted(sto_to_kill_chain_phases[story['name']])
        if story['name'] in sto_to_ciss:
            story['ciss'] = sorted(sto_to_ciss[story['name']])
        if story['name'] in sto_to_nists:
            story['nists'] = sorted(sto_to_nists[story['name']])

    #sort stories into categories
    categories = []
    category_names = set()
    for story in stories:
        if 'category' in story['tags']:
            category_names.add(story['tags']['category'][0])

    for category_name in sorted(category_names):
        new_category = {}
        new_category['name'] = category_name
        new_category['stories'] = []
        categories.append(new_category)

    for story in stories:
        for category in categories:
            if category['name'] == story['tags']['category'][0]:
                category['stories'].append(story)

    return categories


def write_splunk_docs(stories, detections, OUTPUT_DIR):

    categories = prepare_content(stories, detections)

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('splunk_docs_categories.j2')
    output_path = OUTPUT_DIR + "/splunk_docs_categories.wiki"
    output = template.render(categories=categories)
    with open(output_path, 'w') as f:
        f.write(output)

    return len(stories), output_path


def write_markdown_docs(stories, detections, OUTPUT_DIR):

    categories = prepare_content(stories, detections)

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('stories_categories.j2')
    output_path = OUTPUT_DIR + "/stories_categories.md"
    output = template.render(categories=categories)
    with open(output_path, 'w') as f:
        f.write(output)

    return len(stories), output_path






# function to get unique values
def unique(list1):
    # init a null list
    unique_list = []
    # traverse for all elements
    for x in list1:
        # check if exists in unique_list or not
        if x not in unique_list:
            unique_list.append(x)
    return unique_list


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


def process_metadata(detections, story_name):
    # grab mappings
    mappings = dict()

    # grab provising technologies
    providing_technologies = []

    # grab datamodels
    data_models = []

    # process the above for detections
    for detection_name, detection in sorted(detections.items()):
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

            for key in detection['mappings'].keys():
                mappings[key] = list(detection['mappings'][key])

    return mappings, providing_technologies, data_models


def generate_detections(REPO_PATH, stories):
    # first we process detections

    detections = []
    detections_manifest_files = path.join(path.expanduser(REPO_PATH), "detections/*.yml")
    for detections_manifest_file in glob.glob(detections_manifest_files):

        # read in each detection
        with open(detections_manifest_file, 'r') as stream:
            try:
                detection = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit("ERROR: reading {0}".format(detections_manifest_file))

        detections.append(detection)

    complete_detections = dict()
    for detection in detections:
        # lets process v1 detections
        if detection['spec_version'] == 1:
            if verbose:
                print("processing v1 detection: {0}".format(detection['search_name']))
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
            for story_name, story in sorted(stories.items()):
                for d in story['detections']:
                    if d['name'] == name:
                        if 'investigations' in story:
                            investigations = story['investigations']
                        if 'baselines' in story:
                            baselines = story['baselines']

        # lets process v2 detections
        if detection['spec_version'] == 2:
            if verbose:
                print("processing v2 detection: {0}".format(detection['name']))
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
                uba = detection['detect']['uba']
                type = 'uba'
                search = uba['search'] = 'CONSTRUCT DETECTION SEARCH HERE'
                # earliest_time = uba['earliest_time']
                # latest_time = uba['latest_time']
                # cron = uba['cron_schedule']

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
        for story_name, story in sorted(stories.items()):
            for d in story['detections']:
                if d['name'] == name:
                    complete_detections[name]['stories'].append(story['story_name'])

        # sort uniq the results
        complete_detections[name]['stories'] = sorted(set(complete_detections[name]['stories']))

    return complete_detections


def generate_stories(REPO_PATH, verbose):
    story_files = []
    story_manifest_files = path.join(path.expanduser(REPO_PATH), "stories/*.yml")

    for story_manifest_file in glob.glob(story_manifest_files):

        # read in each story
        with open(story_manifest_file, 'r') as stream:
            try:
                story = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit("ERROR: reading {0}".format(story_manifest_file))

        story_files.append(story)

    # store an object with all stories and their data

    complete_stories = dict()
    for story in story_files:
        if verbose:
            print("processing story: {0}".format(story['name']))
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


def write_splunk_docs_bak(stories, detections, OUTPUT_DIR):

    paths = []
    # Create conf files from analytics stories files
    splunk_docs_output_path = OUTPUT_DIR + "/splunk_docs_categories.wiki"
    paths.append(splunk_docs_output_path)
    output_file = open(splunk_docs_output_path, 'w')
    output_file.write("= Use Case Categories=\n")
    output_file.write("The collapse...\n")

    # calculate categories
    categories = []
    for story_name, story in sorted(stories.items()):
        c = story['category']
        categories.append(c)

    # get a unique set of them
    categories = unique(categories)
    for c in categories:
        output_file.write("\n\n=={0}==\n".format(c[0]))

        # iterate through every story and print it out
        for story_name, story in sorted(stories.items()):
            # if the category matches
            if story['category'] == c:
                output_file.write("\n==={0}===\n".format(story_name))
                output_file.write("\n{0}\n".format(story['description']))
                output_file.write(
                    """\n<div class="toccolours mw-collapsible">\n<div class="mw-collapsible-content">\n""")
                # header information
                output_file.write("\n====Narrative====\n{0}\n".format(story['narrative']))

                mappings, providing_technologies, data_models = process_metadata(detections, story_name)

                # providing tech
                output_file.write("\n====Providing Technologies====\n")
                providing_technologies = unique(providing_technologies)
                for pt in providing_technologies:
                    output_file.write("* {0}\n".format(pt))

                # providing tech
                output_file.write("\n====Data Models====\n")
                data_models = unique(data_models)
                for dm in data_models:
                    output_file.write("* {0}\n".format(dm))

                # mappings
                output_file.write("\n====Mappings====\n")

                output_file.write("\n=====ATT&CK=====\n")
                if mappings['mitre_attack']:
                    for m in mappings['mitre_attack']:
                        output_file.write("* {0}\n".format(m))

                output_file.write("\n=====Kill Chain Phases=====\n")
                if mappings['kill_chain_phases']:
                    for m in mappings['kill_chain_phases']:
                        output_file.write("* {0}\n".format(m))

                if mappings['cis20']:
                    output_file.write("\n=====CIS=====\n")
                    for m in mappings['cis20']:
                        output_file.write("* {0}\n".format(m))

                if mappings['nist']:
                    output_file.write("\n=====NIST=====\n")
                    for m in mappings['nist']:
                        output_file.write("* {0}\n".format(m))

                # references
                output_file.write("\n====References====\n")
                for r in story['references']:
                    output_file.write("* {0}\n".format(r))

                # story details
                output_file.write("\ncreation_date = {0}\n\n".format(story['creation_date']))
                output_file.write("modification_date = {0}\n\n".format(story['modification_date']))
                output_file.write("version = {0}\n".format(story['version']))

                # footer information
                output_file.write("""\n</div>\n</div>\n""")
    output_file.write("""\n[[Category:V:Lab:drafts]]""")

    output_file.close()
    story_count = len(stories.keys())
    return story_count, paths


def write_markdown_docs_bak(stories, detections, OUTPUT_DIR):
    paths = []
    # Create conf files from analytics stories files
    splunk_docs_output_path = OUTPUT_DIR + "/stories_categories.md"
    paths.append(splunk_docs_output_path)
    output_file = open(splunk_docs_output_path, 'w')
    output_file.write("# Categories\n")
    output_file.write("Analytics stories organized by categories\n")

    # calculate categories
    categories = []
    for story_name, story in sorted(stories.items()):
        c = story['category']
        categories.append(c)

    # get a unique set of them
    categories = unique(categories)

    # build category TOC
    for c in categories:
        output_file.write("\n* [{0}](#{1})\n".format(c[0], c[0].replace(' ', '-').lower()))

    for c in categories:
        output_file.write("\n\n## {0}\n".format(c[0]))

        # build story TOC
        for story_name, story in sorted(stories.items()):
            # if the category matches
            if story['category'] == c:
                output_file.write("\n* [{0}](#{1})\n".format(story_name, story_name.replace(' ', '-').lower()))

        # iterate through every story and print it out
        for story_name, story in sorted(stories.items()):
            # if the category matches
            if story['category'] == c:
                output_file.write("\n### {0}\n".format(story_name))
                # basic story info
                output_file.write("* id = `{0}`\n".format(story['id']))
                output_file.write("* creation_date = {0}\n".format(story['creation_date']))
                output_file.write("* modification_date = {0}\n".format(story['modification_date']))
                output_file.write("* version = {0}\n".format(story['version']))
                output_file.write("* spec_version = {0}\n".format(story['spec_version']))

                # description and narrative
                output_file.write("\n##### Description\n{0}\n".format(story['description']))
                output_file.write("\n##### Narrative\n{0}\n".format(story['narrative']))

                # process detections
                output_file.write("\n##### Detections\n")
                # write all detections
                if 'detections' in story:
                    for d in story['detections']:
                        output_file.write("* {0}\n".format(d['name']))

                mappings, providing_technologies, data_models = process_metadata(detections, story_name)

                # providing tech
                output_file.write("\n##### Providing Technologies\n")
                providing_technologies = unique(providing_technologies)
                for pt in providing_technologies:
                    output_file.write("* {0}\n".format(pt))

                # data models
                output_file.write("\n##### Data Models\n")
                data_models = unique(data_models)
                for dm in data_models:
                    output_file.write("{0}\n".format(dm))

                # mappings
                output_file.write("\n##### Mappings\n")

                output_file.write("\n###### ATT&CK\n")
                if mappings['mitre_attack']:
                    for m in mappings['mitre_attack']:
                        output_file.write("* {0}\n".format(m))

                output_file.write("\n###### Kill Chain Phases\n")
                if mappings['kill_chain_phases']:
                    for m in mappings['kill_chain_phases']:
                        output_file.write("* {0}\n".format(m))

                if mappings['cis20']:
                    output_file.write("\n###### CIS\n")
                    for m in mappings['cis20']:
                        output_file.write("* {0}\n".format(m))

                if mappings['nist']:
                    output_file.write("\n###### NIST\n")
                    for m in mappings['nist']:
                        output_file.write("* {0}\n".format(m))

                # maintainers
                output_file.write("\n##### Maintainers\n")
                for m in story['maintainers']:
                    output_file.write("* name = {0}\n".format(m['name']))
                    output_file.write("* email = {0}\n".format(m['email']))
                    output_file.write("* company = {0}\n".format(m['company']))

                # references
                output_file.write("\n##### References\n")
                for r in story['references']:
                    output_file.write("* {0}\n".format(r))

    output_file.close()
    story_count = len(stories.keys())
    return story_count, paths


def parse_data_models_from_search(search):
    match = re.search('from\sdatamodel\s?=\s?([^\s.]*)',search)
    if match is not None:
        return match.group(1)
    return False

if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="generates documentation from our content", epilog="""
    This tool converts manifests information to documents in variious format like markdown and wiki markup used by Splunk docs.""")
    parser.add_argument("-p", "--path", required=True, help="path to security_content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory for the docs")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    parser.add_argument("-gsd", "--gen_splunk_docs", required=False, default=True, action='store_true',
                        help="generates wiki markup splunk documentation, default to true")
    parser.add_argument("-gmd", "--gen_markdown_docs", required=False, default=True, action='store_true',
                        help="generates markdown docs, default to true")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_DIR = args.output
    verbose = args.verbose
    gsd = args.gen_splunk_docs
    gmd = args.gen_markdown_docs

    stories = load_objects("stories/*.yml")
    detections = []
    detections = load_objects("detections/*/*.yml")
    detections.extend(load_objects("detections/*/*/*.yml"))

    # complete_stories = generate_stories(REPO_PATH, verbose)
    # complete_detections = generate_detections(REPO_PATH, complete_stories)

    if gsd:
        story_count, path = write_splunk_docs(stories, detections, OUTPUT_DIR)
        print("{0} story documents have been successfully written to {1}".format(story_count, path))
    else:
        print("--gen_splunk_docs  was set to false, not generating splunk documentation")

    if gmd:
        story_count, path = write_markdown_docs(stories, detections,  OUTPUT_DIR)
        print("{0} story documents have been successfully written to {1}".format(story_count, path))
    else:
        print("--gen_splunk_docs  was set to false, not generating splunk documentation")

    print("documentation generation for security content completed..")
