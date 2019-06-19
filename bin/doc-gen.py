import glob
import json
import argparse
from os import path
import sys


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


def write_splunk_docs(stories, OUTPUT_DIR):

    paths = []
    # Create conf files from analytics stories files
    splunk_docs_output_path = OUTPUT_DIR + "/splunk_docs_categories.wiki"
    paths.append(splunk_docs_output_path)
    output_file = open(splunk_docs_output_path, 'w')
    output_file.write("= Use Case Categories=\n")
    output_file.write("The collapse...\n")

    # calculate categories
    categories = []
    for story_name, story in sorted(stories.iteritems()):
        c = story['category']
        categories.append(c)

    # get a unique set of them
    categories = unique(categories)
    for c in categories:
        output_file.write("\n\n=={0}==\n".format(c[0]))

        # iterate through every story and print it out
        for story_name, story in sorted(stories.iteritems()):
            # if the category matches
            if story['category'] == c:
                output_file.write("\n==={0}===\n".format(story_name))

                # header information
                output_file.write("""
                                 <div class="toccolours mw-collapsible">
                                 <div class="mw-collapsible-content">
                                 """)

                output_file.write("'''Description''' <br/>\n{0}\n\n".format(story['description']))
                output_file.write("'''Narrative''' <br/>\n{0}\n\n".format(story['narrative']))

                # print mappings
                output_file.write("""
                ''' Framework Mappings ''' <br/>
                '''ATT&CK''':  <br/>
                '''Kill Chain Phases''': Actions on Objectives<br/>
                '''CIS 20''': CIS 11, CIS 12<br/>
                '''NIST''': PR.PT, DE.AE, PR.IP<br/>

                '''Data Dependencies'''
                '''Data Models''': <br/>
                '''Providing Technologies''': <br/>
                \n
                """)

                # footer information
                output_file.write("""
                </div></div>
                """)

    output_file.close()
    story_count = len(stories.keys())
    return story_count, paths


def write_markdown_docs(stories, OUTPUT_DIR):
    paths = []
    # Create conf files from analytics stories files
    splunk_docs_output_path = OUTPUT_DIR + "/stories_categories.md"
    paths.append(splunk_docs_output_path)
    output_file = open(splunk_docs_output_path, 'w')
    output_file.write("# Categories\n")
    output_file.write("Analytics stories organized by categories\n")

    # calculate categories
    categories = []
    for story_name, story in sorted(stories.iteritems()):
        c = story['category']
        categories.append(c)

    # get a unique set of them
    categories = unique(categories)

    # build category table
    for c in categories:
        output_file.write("\n* [{0}](#{1})\n".format(c[0], c[0].replace(' ', '-').lower()))

    for c in categories:
        output_file.write("\n\n## {0}\n".format(c[0]))

        # iterate through every story and print it out
        for story_name, story in sorted(stories.iteritems()):
            # if the category matches
            if story['category'] == c:
                output_file.write("\n### {0}\n".format(story_name))
                # basic story info
                output_file.write("* creation_date = {0}\n".format(story['creation_date']))
                output_file.write("* modification_date = {0}\n".format(story['modification_date']))
                output_file.write("* id = {0}\n".format(story['id']))
                output_file.write("* version = {0}\n".format(story['version']))
                output_file.write("* spec_version = {0}\n".format(story['spec_version']))

                # description and narrative
                output_file.write("\n##### Description\n{0}\n".format(markdown(story['description'])))
                output_file.write("\n##### Narrative\n{0}\n".format(markdown(story['narrative'])))

                # mappings
                output_file.write("\n##### Mappings\n")
                output_file.write("ATT&CK: \n")

                # maintainers
                output_file.write("\n##### Maintainers\n")
                for m in story['maintainers']:
                    output_file.write("* name = {0}\n".format(m['name']))
                    output_file.write("* email = {0}\n".format(m['company']))
                    output_file.write("* company = {0}\n".format(m['email']))

                # references
                output_file.write("\n##### References\n")
                for r in story['references']:
                    output_file.write("* {0}\n".format(markdown(r)))

    output_file.close()
    story_count = len(stories.keys())
    return story_count, paths


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="generates documentation from our content", epilog="""
    This tool converts manifests information to documents in variious format like markdown and wiki markup used by Splunk docs.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-content repo")
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

    complete_stories = generate_stories(REPO_PATH, verbose)

    if gsd:
        story_count, paths = write_splunk_docs(complete_stories, OUTPUT_DIR)
        for p in paths:
            print "{0} story documents have been successfully written to {1}".format(story_count, p)
    else:
        print "--gen_splunk_docs  was set to false, not generating splunk documentation"

    if gmd:
        story_count, paths = write_markdown_docs(complete_stories, OUTPUT_DIR)
        for p in paths:
            print "{0} story documents have been successfully written to {1}".format(story_count, p)
    else:
        print "--gen_splunk_docs  was set to false, not generating splunk documentation"

    print "documentation generation for security content completed.."
