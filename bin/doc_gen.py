import glob
import yaml
import argparse
from os import path, walk
import sys
import re
from jinja2 import Environment, FileSystemLoader




def generate_doc_detections(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, VERBOSE):

    types = ["endpoint", "application", "cloud", "deprecated", "experimental", "network", "web"]
    manifest_files = []
    for t in types:
        for root, dirs, files in walk(REPO_PATH + '/detections/' + t):
            for file in files:
                if file.endswith(".yml"):
                    manifest_files.append((path.join(root, file)))

    detections = []
    for manifest_file in manifest_files:
        detection_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue
        detection_yaml = object
        detection_yaml['kind'] = manifest_file.split('/')[-2]
        detections.append(detection_yaml)

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                             trim_blocks=True)
    template = j2_env.get_template('doc_detections_markdown.j2')
    output_path = path.join(OUTPUT_DIR + '/detections.md')
    output = template.render(detections=detections)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    print("doc_gen.py wrote {0} detection documentation to: {1}".format(len(detections),output_path))




    return False

if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates documentation from Splunk Security Content", epilog="""
    This tool converts all Splunk Security Content detections, stories, workbooks and spec files into documentation. It builds both wiki markup (Splunk Docs) an markdown documentation.""")
    parser.add_argument("-p", "--path", required=True, help="path to security_content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory for the docs")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    parser.add_argument("-t", "--type", required=False, default="all", help="type of content to generate documentation for, supports `detections`, `stories`, `spec`, and `all`, defaults to `all`" )

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_DIR = args.output
    VERBOSE = args.verbose
    type = args.type

    allowed_types = ['stories', 'detections', 'spec', 'all']
    if type not in allowed_types:
        print("ERROR: the type {0} is not support, the current support types are: {1}".format(type,allowed_types))
        parser.print_help()
        sys.exit(1)

    TEMPLATE_PATH = path.join(REPO_PATH, 'bin/jinja2_templates')

    if type == 'all':
        generate_doc_detections(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, VERBOSE)


    print("finished successfully!")

#    stories = load_objects("stories/*.yml")
#    detections = []
#    detections = load_objects("detections/*/*.yml")
#    detections.extend(load_objects("detections/*/*/*.yml"))


    #story_count, path = write_splunk_docs(stories, detections, OUTPUT_DIR)
    #print("{0} story documents have been successfully written to {1}".format(story_count, path))
