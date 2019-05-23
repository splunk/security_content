# Take the manifest files and build files for Enterprise Security Content Updates with markdown syntax


import datetime
import glob
import json
import os
import argparse

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


def main():
    # Create conf files from manifest files
    ssconf = open(OUTPUT_DIRECTORY + 'savedsearches.conf', 'w')
    asconf = open(OUTPUT_DIRECTORY + 'analytic_stories.conf', 'w')

    story_manifests = []
    for story_manifest_file in glob.glob(os.path.join(MANIFEST_DIRECTORY, '*/stories/*.json')):
        try:
            story_manifest_data = json.loads(open(story_manifest_file, 'r').read())
        except Exception as e:
            print "Error reading %s" % story_manifest_file
            print e
            continue

        story_manifests.append(story_manifest_data)

    search_manifests = {}
    for search_manifest_file in glob.glob(os.path.join(MANIFEST_DIRECTORY, '*/searches/*.json')):
        try:
            search_manifest = json.loads(open(search_manifest_file, 'r').read())
        except Exception as e:
            print "Error reading %s" % search_manifest_file
            print e
            continue

        search_manifests[search_manifest['search_name']] = search_manifest

    full_stories = {}
    for story in story_manifests:
        # Start building the story for the use case
        full_stories[story['name']] = {}
        full_stories[story['name']]['story_name'] = story['name']
        full_stories[story['name']]['id'] = story['id']
        if 'modification_date' in story:
            full_stories[story['name']]['modification_date'] = story['modification_date']
        else:
            full_stories[story['name']]['modification_date'] = story['creation_date']
        full_stories[story['name']]['creation_date'] = story['creation_date']
        full_stories[story['name']]['description'] = story['description']
        if 'references' not in story:
            story['references'] = []
        full_stories[story['name']]['references'] = story['references']
        full_stories[story['name']]['category'] = story['category']
        full_stories[story['name']]['version'] = story['version']
        full_stories[story['name']]['mappings'] = {}
        full_stories[story['name']]['data_models'] = set()
        full_stories[story['name']]['providing_technologies'] = set()
        full_stories[story['name']]['tags'] = set()
        full_stories[story['name']]['narrative'] = story['narrative']

        full_stories[story['name']]['detection_searches'] = []
        full_stories[story['name']]['investigative_searches'] = []
        full_stories[story['name']]['contextual_searches'] = []
        full_stories[story['name']]['support_searches'] = []
        all_searches = []
        if 'detection_searches' in story['searches']:
            full_stories[story['name']]['detection_searches'] = ["ESCU - %s - Rule" % ds for ds in
                                                                 story['searches']['detection_searches']]
            all_searches += story['searches']['detection_searches']
        if 'investigative_searches' in story['searches']:
            full_stories[story['name']]['investigative_searches'] = ["ESCU - " + invs for invs in
                                                                     story['searches']['investigative_searches']]
            all_searches += story['searches']['investigative_searches']
        if 'contextual_searches' in story['searches']:
            full_stories[story['name']]['contextual_searches'] = ["ESCU - " + cs for cs in
                                                                  story['searches']['contextual_searches']]
            all_searches += story['searches']['contextual_searches']
        if 'support_searches' in story['searches']:
            full_stories[story['name']]['support_searches'] = ["ESCU - " + ss for ss in
                                                               story['searches']['support_searches']]
            all_searches += story['searches']['support_searches']

        # Mark each search with what analytic stories it belongs too
        for search in all_searches:
            if search not in search_manifests:
                continue

            if 'analytic_story' not in search_manifests[search]:
                search_manifests[search]['analytic_story'] = []

            search_manifests[search]['analytic_story'].append(story['name'])

    for key, search in search_manifests.iteritems():
        # Gather the next steps
        contextual_searches = []
        investigative_searches = []
        if 'analytic_story' in search:
            for analytic_story in search['analytic_story']:
                if not analytic_story:
                    continue

                if 'mappings' in search:
                    for map_key in search['mappings']:
                        if map_key not in full_stories[analytic_story]['mappings']:
                            full_stories[analytic_story]['mappings'][map_key] = set()

                        for mapping in search['mappings'][map_key]:
                            full_stories[analytic_story]['mappings'][map_key].add(mapping)

                if 'data_models' in search['data_metadata']:
                    for dm in search['data_metadata']['data_models']:
                        full_stories[analytic_story]['data_models'].add(dm)

                if 'providing_technologies' in search['data_metadata']:
                    for tex in search['data_metadata']['providing_technologies']:
                        full_stories[analytic_story]['providing_technologies'].add(tex)

                search_mod = datetime.datetime.strptime(search['modification_date'], "%Y-%m-%d")
                latest_story_mod = datetime.datetime.strptime(full_stories[analytic_story]['modification_date'], "%Y-%m-%d")
                if search_mod > latest_story_mod:
                    full_stories[analytic_story]['modification_date'] = search_mod.strftime("%Y-%m-%d")

            if search['search_type'] == 'detection':
                contextual_searches.extend(full_stories[analytic_story]['contextual_searches'])
                investigative_searches.extend(full_stories[analytic_story]['investigative_searches'])

        contextual_searches = sorted(list(set(contextual_searches)))
        investigative_searches = sorted(list(set(investigative_searches)))

        if 'correlation_rule' in search:
            stanza_name = "ESCU - %s - Rule" % search['search_name'][0:86]
        else:
            stanza_name = "ESCU - %s" % search['search_name'][0:93]

        ssconf.write("[%s]\n" % stanza_name)
        ssconf.write("action.escu = 0\n")
        ssconf.write("action.escu.enabled = 1\n")
        ssconf.write("action.escu.creation_date = %s\n" % search['creation_date'])
        if 'modification_date' in search:
            ssconf.write("action.escu.modification_date = %s\n" % search['modification_date'])
        else:
            ssconf.write("action.escu.modification_date = %s\n" % search['creation_date'])

        if 'asset_type' in search:
            ssconf.write("action.escu.asset_at_risk = %s\n" % search['asset_type'])
        if 'channel' in search:
            ssconf.write("action.escu.channel = %s\n" % search['channel'])
        if 'confidence' in search:
            ssconf.write("action.escu.confidence = %s\n" % search['confidence'])
        if 'eli5' in search:
            eli5 = markdown(search['eli5'])
            ssconf.write("action.escu.eli5 = %s\n" % eli5)
        else:
            ssconf.write("action.escu.eli5 = none\n")

        if 'how_to_implement' in search:
            how_to_implement = markdown(search['how_to_implement'])
            ssconf.write("action.escu.how_to_implement = %s\n" % how_to_implement)
        else:
            ssconf.write("action.escu.how_to_implement = none\n")

        if 'data_models' in search['data_metadata']:
            ssconf.write("action.escu.data_models = %s\n" % json.dumps(search['data_metadata']['data_models']))

        if search['search_type'] == 'detection':
            ssconf.write("action.escu.full_search_name = ESCU - %s - Rule\n" % search['search_name'])
        else:
            ssconf.write("action.escu.full_search_name = ESCU - %s\n" % search['search_name'])
        if 'mappings' in search:
            ssconf.write("action.escu.mappings = %s\n" % json.dumps(search['mappings']))
        if 'known_false_positives' in search:
            known_false_positives = markdown(search['known_false_positives'])
            ssconf.write("action.escu.known_false_positives = %s\n" % known_false_positives)
        else:
            ssconf.write("action.escu.known_false_positives = None at this time\n")

        if 'search_type' in search:
            ssconf.write("action.escu.search_type = %s\n" % search['search_type'])
        if 'providing_technologies' in search['data_metadata']:
            ssconf.write("action.escu.providing_technologies = %s\n" %
                         json.dumps(search['data_metadata']['providing_technologies']))
        if 'analytic_story' in search:
            ssconf.write("action.escu.analytic_story = %s\n" % json.dumps(search['analytic_story']))
        if 'fields_required' in search:
            ssconf.write("action.escu.fields_required = %s\n" % json.dumps(search['fields_required']))
        if 'search_window' in search:
            ssconf.write("action.escu.earliest_time_offset = %s\n" % search['search_window']['earliest_time_offset'])
            ssconf.write("action.escu.latest_time_offset = %s\n" % search['search_window']['latest_time_offset'])

        if 'phantom_playbooks' in search:

            for p in (search['phantom_playbooks']):
                ssconf.write("action.runphantomplaybook = 1\n")
                ssconf.write("action.runphantomplaybook.param.phantom_server = %s\n" % p['phantom_server'])
                ssconf.write("action.runphantomplaybook.param.playbook_name = %s\n" % p['playbook_name'])
                ssconf.write("action.runphantomplaybook.param.playbook_display_name = %s\n" % p['playbook_display_name'])
                ssconf.write("action.runphantomplaybook.param.playbook_url = %s\n" % p['playbook_url'])
                ssconf.write("action.runphantomplaybook.param.sensitivity = %s\n" % p['sensitivity'])
                ssconf.write("action.runphantomplaybook.param.severity = %s\n" % p['severity'])

        if 'correlation_rule' in search:
            ssconf.write("action.correlationsearch.enabled = 1\n")
            ssconf.write("action.correlationsearch.label = %s\n" % search['search_name'])

            if 'notable' in search['correlation_rule']:
                ssconf.write("action.notable = 1\n")
                if 'nes_fields' in search['correlation_rule']['notable']:
                    ssconf.write("action.notable.param.nes_fields = %s\n" % search['correlation_rule']['notable']['nes_fields'])
                ssconf.write("action.notable.param.rule_description = %s\n" %
                             search['correlation_rule']['notable']['rule_description'])
                ssconf.write("action.notable.param.rule_title = %s\n" %
                             search['correlation_rule']['notable']['rule_title'])
                ssconf.write("action.notable.param.security_domain = %s\n" % search['security_domain'])
                ssconf.write("action.notable.param.severity = %s\n" % search['confidence'])

                cs_string = ""
                for cs in contextual_searches:
                    cs_string += "     - %s\\n" % cs

                invs_string = ""
                for invs in investigative_searches:
                    invs_string += "     - %s\\n" % invs

                if 'phantom_playbooks' in search:

                    for p in (search['phantom_playbooks']):
                        playbook_next_steps_string = "Splunk>Phantom Response Playbook - Monitor enrichment of the \
                            Splunk>Phantom Playbook called " + str(p['playbook_display_name']) + " and answer any \
                            analyst prompt in Mission Control with a response decision. \
                            Link to the playbook " + str(p['playbook_url'])
                        next_steps = "{\"version\": 1, \"data\": \"Recommended following \
                            steps:\\n\\n1. [[action|runphantomplaybook]]: Phantom playbook \
                            recommendations:\\n%s\\n2. [[action|escu_contextualize]]: Based \
                            on ESCU context gathering recommendations:\\n%s\\n3. [[action|escu_investigate]]: \
                            Based on ESCU investigate recommendations:\\n%s\"}" % (playbook_next_steps_string,
                                                                                   cs_string, invs_string)
                        ssconf.write("action.notable.param.next_steps = %s\n" % next_steps)
                        ssconf.write("action.notable.param.recommended_actions = runphantomplaybook, \
                            escu_contextualize, escu_investigate\n")

                elif 'phantom_playbooks' not in search:

                    next_steps = "{\"version\": 1, \"data\": \"Recommended following steps:\\n\\n1. \
                            [[action|escu_contextualize]]: Based on ESCU context gathering recommendations:\\n%s\\n2. \
                            [[action|escu_investigate]]: Based on ESCU investigate \
                            recommendations:\\n%s\"}" % (cs_string, invs_string)
                    ssconf.write("action.notable.param.next_steps = %s\n" % next_steps)
                    ssconf.write("action.notable.param.recommended_actions = escu_contextualize, escu_investigate\n")

            if 'risk' in search['correlation_rule']:
                ssconf.write("action.risk = 1\n")
                ssconf.write("action.risk.param._risk_object = %s\n" % search['correlation_rule']['risk']['risk_object'])
                try:
                    ssconf.write("action.risk.param._risk_object_type = %s\n" %
                                 search['correlation_rule']['risk']['risk_object_type'][0])
                except Exception as e:
                    print "Error is risk object type %s" % search['correlation_rule']['risk']['risk_object_type']
                    print
                    continue

                if len(search['correlation_rule']['risk']['risk_object_type']) > 1:
                    print "Error there is more than 1 risk object type %s" % search['correlation_rule']['risk']['risk_object_type']

                ssconf.write("action.risk.param._risk_score = %d\n" % search['correlation_rule']['risk']['risk_score'])
                ssconf.write("action.risk.param.verbose = 0\n")

            if 'suppress' in search['correlation_rule']:
                ssconf.write("alert.digest_mode = 1\n")
                ssconf.write("alert.suppress = 1\n")
                ssconf.write("alert.suppress.fields = %s\n" % search['correlation_rule']['suppress']['suppress_fields'])
                ssconf.write("alert.suppress.period = %s\n" % search['correlation_rule']['suppress']['suppress_period'])

        if 'scheduling' in search and 'cron_schedule' in search['scheduling']:
            ssconf.write("cron_schedule = %s\n" % search['scheduling']['cron_schedule'])

        search_description = markdown(search['search_description'])
        ssconf.write("description = %s\n" % search_description)
        if 'scheduling' in search:
            ssconf.write("dispatch.earliest_time = %s\n" % search['scheduling']['earliest_time'])
            ssconf.write("dispatch.latest_time = %s\n" % search['scheduling']['latest_time'])

        ssconf.write("disabled=true\n")
        if search['search_type'] == 'detection':
            ssconf.write("enableSched = 1\n")
            ssconf.write("counttype = number of events\n")
            ssconf.write("relation = greater than\n")
            ssconf.write("quantity = 0\n")
        ssconf.write("realtime_schedule = 0\n")
        ssconf.write("schedule_window = auto\n")
        ssconf.write("is_visible = false\n")

        search = markdown(search['search'])
        ssconf.write("search = %s\n" % search)
        ssconf.write("\n")

    # Finish the story
    for story_name, story in sorted(full_stories.iteritems()):
        asconf.write("[%s]\n" % story_name)
        asconf.write("category = %s\n" % story['category'])
        asconf.write("creation_date = %s\n" % story['creation_date'])
        data_models = list(story['data_models'])
        if data_models:
            data_models.sort()
            asconf.write("data_models = %s\n" % json.dumps(data_models))
        else:
            asconf.write("data_models =\n")
        description = markdown(story['description'])
        asconf.write("description = %s\n" % description)
        asconf.write("id = %s\n" % story['id'])
        asconf.write("version = %s\n" % story['version'])

        if 'mappings' in story:
            for key in story['mappings'].keys():
                story['mappings'][key] = list(story['mappings'][key])
            asconf.write("mappings = %s\n" % json.dumps(story['mappings']))

        asconf.write("modification_date = %s\n" % story['modification_date'])

        asconf.write("reference = %s\n" % json.dumps(story['references']))
        tex = list(story['providing_technologies'])
        tex.sort()
        asconf.write("providing_technologies = %s\n" % json.dumps(tex))
        if story['detection_searches']:
            asconf.write("detection_searches = %s\n" % json.dumps(story['detection_searches']))
        if story['investigative_searches']:
            asconf.write("investigative_searches = %s\n" % json.dumps(story['investigative_searches']))
        if story['contextual_searches']:
            asconf.write("contextual_searches = %s\n" % json.dumps(story['contextual_searches']))
        if story['support_searches']:
            asconf.write("support_searches = %s\n" % json.dumps(story['support_searches']))
        if story['narrative']:
            narrative = markdown(story['narrative'])
            asconf.write("narrative = %s\n" % narrative)
        asconf.write("\n")

    usconf = open('src/default/usage_searches.conf', 'r')
    usage_searches = usconf.read()
    usconf.close()
    ssconf.write('####################################################################\n\n')
    ssconf.write(usage_searches)
    asconf.close()
    ssconf.close()

    print "-----> ESCU ------- analytic_stories.conf file written for ESCU with Markdown"
    print "-----> ESCU------- savedsearches.conf file written for ESCU with Markdown"


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="converts security-content manifests to source files", epilog="""
    This tool converts manifests to the source files to be used by products, specfically Splunk's.
    It generates the savesearches.conf, analyticsstories.conf files for ES.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-security content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory")

    # parse them
    args = parser.parse_args()
    MANIFEST_DIRECTORY = args.path
    OUTPUT_DIRECTORY = args.output

    main()
