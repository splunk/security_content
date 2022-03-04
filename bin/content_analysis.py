import glob
import yaml
import sys
import re
import argparse

from os import path


def load_objects(file_path, REPO_PATH):
    files = []
    manifest_files = path.join(path.expanduser(REPO_PATH), file_path)
    for file in sorted(glob.glob(manifest_files)):
        files.append(load_file(file))
    return files


def load_file(file_path):
    with open(file_path, 'r', encoding="utf-8") as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def load_content(old_project):
    stories = load_objects("stories/*.yml", old_project)
    macros = load_objects("macros/*.yml", old_project)
    lookups = load_objects("lookups/*.yml", old_project)
    baselines = load_objects("baselines/*.yml", old_project)
    responses = load_objects("responses/*.yml", old_project)
    response_tasks = load_objects("response_tasks/*.yml", old_project)
    deployments = load_objects("deployments/*.yml", old_project)

    # process all detections
    detections = []
    detections = load_objects("detections/*/*.yml", old_project)
    detections.extend(load_objects("detections/*/*/*.yml", old_project))

    #print(len(detections))

    return detections, stories, macros, lookups, baselines, responses, response_tasks, deployments


def add_required_field(detections, new_project):
    #for detection in detections:
    matches = re.findall(r'(?<key>[^\s]*)=', detections[0])
    for match in matches:
        print(match)


def main(new_project, old_project, change):

    detections, stories, macros, lookups, baselines, responses, response_tasks, deployments = load_content(old_project)

    if change == "add_required_field":
        add_required_field(detections, new_project)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="applies security content changes to the whole project")
    parser.add_argument("-np", "--new_project", required=True, help="the security content project to write the new configs in to")
    parser.add_argument("-op", "--old_project", required=True, help="the security content project to read the files from")
    parser.add_argument("-c", "--change", required=True, help="the name of your change")

   # parse them
    args = parser.parse_args()
    new_project = args.new_project
    old_project = args.old_project
    change = args.change

    main(new_project, old_project, change)
