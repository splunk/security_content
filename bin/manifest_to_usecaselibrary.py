'''
Take the manifest files and build files for Enterprise Security
'''
import datetime
import glob
import json
import os
import pprint
import re

ALL_UUIDS = []

MANIFEST_DIRECTORY = "."
OUTPUT_DIRECTORY = 'src/default/'

def markdown(x):
  markdown=str(x)


  #code and bold tags
  markdown = markdown.replace("<code>","`")
  markdown = markdown.replace("</code>","`")
  markdown = markdown.replace("<b>","**")
  markdown = markdown.replace("</b>","**")
  #list tag replacements
  markdown = markdown.replace("<ol><li>","\\\n\\\n1. ")
  markdown = markdown.replace("</li><li>","\\\n\\\n1. ")
  markdown = markdown.replace("</li></ol>","")
  markdown = markdown.replace("</li></ul>","")
  markdown = markdown.replace("<ul><li>","\\\n\\\n1. ")

  #break tags replacements
  markdown = markdown.replace("<br></br>","\\\n\\\n")
  markdown = markdown.replace("<br/><br/>","\\\n\\\n")
  markdown = markdown.replace("<br/>","\\\n\\\n")

 #investigative and contextual seaches
  exp ="({\w+})"

  token=re.findall(exp,markdown)
  if token:
    markdown = markdown.replace("{","$")
    markdown = markdown.replace("}","$")
    markdown = markdown.replace("$$","{}")


  return markdown


def main():
    ''' Create conf files from manifest files '''

    test = open(OUTPUT_DIRECTORY + 'analyticstories.conf', 'w')


    story_manifests = []
    for story_manifest_file in glob.glob(os.path.join(MANIFEST_DIRECTORY, '*/stories/*.json')):
        try:
            story_manifest_data = json.loads(open(story_manifest_file, 'r').read())
        except Exception as e:
            print "Error reading %s" % story_manifest_file
            print e
            continue

        story_manifests.append(story_manifest_data)


    #print type(story_manifests)


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
        full_stories[story['name']]['maintainers'] = story['maintainers']
        full_stories[story['name']]['spec_version'] = story['spec_version']
        #print full_stories[story['name']]['maintainers']
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
            full_stories[story['name']]['detection_searches'] = ["ESCU - %s - Rule" % ds for ds in story['searches']['detection_searches']]

            all_searches += story['searches']['detection_searches'] 
            
        if 'investigative_searches' in story['searches']:
            full_stories[story['name']]['investigative_searches'] = ["ESCU - " + invs for invs in story['searches']['investigative_searches']]
            all_searches += story['searches']['investigative_searches']
        if 'contextual_searches' in story['searches']:
            full_stories[story['name']]['contextual_searches'] = ["ESCU - " + cs for cs in story['searches']['contextual_searches']]
            all_searches += story['searches']['contextual_searches']
        if 'support_searches' in story['searches']:
            full_stories[story['name']]['support_searches'] = ["ESCU - " + ss for ss in story['searches']['support_searches']]
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



#Testing a new conf file:
    number = 0
    
    for story_name, story in sorted(full_stories.iteritems()):
                test.write("[analytic_story://%s]\n" % story_name)
                test.write("category = %s\n" % story['category'])
                description = markdown(story['description'])

                test.write("description = %s\n" % description)

                test.write("maintainers = %s\n" % json.dumps(story['maintainers']))
                if story['narrative']:
                    narrative =markdown(story['narrative'])

                    test.write("narrative = %s\n" % narrative)



                test.write("references = %s\n" % json.dumps(story['references']))
             



                # if story['detection_searches']:

                #     #print type(story['detection_searches'])
                #     det=(story['detection_searches'])
                #     #print type(det)

                #     for i in range(len(det)):
                #         #print len(det)
                #         (story['detection_searches']) = str(det[i]) + " - Rule"
                #         searches=(story['detection_searches'])
                    
                # #print (searches)
                # #print "---------------------------------------------------------------"
                # #print "---------------------------------------------------------------"


                # if story['investigative_searches']:
                #     searches = searches + json.dumps(story['investigative_searches'])
                #     #print searches

                # if story['contextual_searches']:
                #     searches = searches + json.dumps(story['contextual_searches'])

                # if story['support_searches']:
                #     searches = searches + json.dumps(story['support_searches'])


                #     #Adding  - Rule by seach and replace

                # searches=searches.replace("][","," )
                # searches=searches.replace("[","," )
                # #searches=searches.replace("\",", " - Rule\",")
                # #searches=searches.replace("\"]", " - Rule\"]")

                if story['detection_searches']:
                    searches=json.dumps(story['detection_searches'])

                if story['investigative_searches']:
                    searches = searches + json.dumps(story['investigative_searches'])

                if story['contextual_searches']:
                    searches = searches + json.dumps(story['contextual_searches'])

                if story['support_searches']:
                    searches = searches + json.dumps(story['support_searches'])


                    #Adding  - Rule by seach and replace

                searches=searches.replace("][","," )
                





                test.write("searches = %s" % searches)
                test.write("\n")
                test.write("spec_version = %s\n" % json.dumps(story['spec_version']))
                test.write("last_updated = %s\n" % story['modification_date'])
                test.write("version = %s\n" % story['version'])
                test.write("\n")
                test.write("\n")


    #testing save searches stanza
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


        if search['search_type'] == 'detection':
              test.write("[savedsearch://ESCU - %s - Rule]\n" % search['search_name'])
        else:
            test.write("[savedsearch://ESCU - %s]\n" % search['search_name'])

        if 'search_type' in search:
            test.write("type = %s\n" % search['search_type'])
        if 'asset_type' in search:
            test.write("asset_type = %s\n" % search['asset_type'])
        if 'confidence' in search:
            test.write("confidence = %s\n" % search['confidence'])
        if 'eli5' in search:
            explanation = markdown(search['eli5'])
            test.write("explanation = %s\n" % explanation)
        else:
            test.write("explanation = none\n")


        if 'how_to_implement' in search:
            how_to_implement = markdown(search['how_to_implement'])
            test.write("how_to_implement = %s\n" % how_to_implement)
        else:
            test.write("how_to_implement = none\n")


        if 'mappings' in search:
            test.write("annotations = %s\n" % json.dumps(search['mappings']))
        if 'known_false_positives' in search:
            known_false_positives = markdown(search['known_false_positives'])
            test.write("known_false_positives = %s\n" % known_false_positives)
        else:
            test.write("known_false_positives = None at this time\n")
            

        if 'providing_technologies' in search['data_metadata']:
            test.write("providing_technologies = %s\n" % json.dumps(search['data_metadata']['providing_technologies']))
        if 'search_window' in search:
            test.write("earliest_time_offset = %s\n" % search['search_window']['earliest_time_offset'])
            test.write("latest_time_offset = %s\n" % search['search_window']['latest_time_offset'])

        test.write("\n")
        test.write("\n")




    usconf = open('src/default/usage_searches.conf', 'r')
    usage_searches = usconf.read()
    usconf.close()


    #ssconf.close()
    test.close()

    print "-----> ES-Hyuara ----- analyticstories.conf file written for Hyuara with Markdown ------------"



if __name__ == "__main__":
    main()
