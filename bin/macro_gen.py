#!/bin/python
from os import path, walk
import sys
import argparse
import yaml
import re
import json

def macro_gen(STRONTIC_PATH, REPO_PATH, VERBOSE):

    macros = []
    macro = dict()

    with open(STRONTIC_PATH, 'r', encoding='utf-8-sig') as file:
        strontic_objects = json.load(file,strict=False)

    for process_object, values in strontic_objects.items():
        if 'meta_original_filename' in values:
            # make macro object
            macro['definition'] = 'Processes.process_name=' + process_object.split("-")[0] + ' OR Processes.original_file_name=' + values['meta_original_filename']
            macro['description'] = "matches the process with its original file name, data for this macro came from: https://strontic.github.io/"
            macro['name'] = process_object.split("-")[0].lower().replace(".", "_")
            macros.append(macro)

            if VERBOSE:
                print("generating macro: {0} with definition: {1}".format(macro['name'], macro['definition']))

    #final_macros = []
    # check for duplicate first
    #for macro in macros:
    #    if macro not in final_macros:
    #        final_macros.append(macro)
        #else:
        #    extended_definition = ' OR Processes.process_name=' + process_object.split("-")[0] + ' OR Processes.original_file_name=' + values['meta_original_filename']
        #    macro['definition'] = macro['definition'] + extended_definition
            #print(macro['definition'])

    #print(macros)
    return len(macros)


def main(args):

    parser = argparse.ArgumentParser(description="keeps yamls in security_content sorted and pretty printed with custom sort keys, \
            meant to run quitely for CI, use -v flag to make it bark")

    parser.add_argument("-s", "--strontic_json", required=True, help="path to strontic json")
    parser.add_argument("-p", "--path", required=True, help="path to security_content repo")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")

    # parse them
    args = parser.parse_args()
    STRONTIC_PATH = args.strontic_json
    REPO_PATH = args.path
    VERBOSE = args.verbose
    generated_count = macro_gen(STRONTIC_PATH, REPO_PATH, VERBOSE)
    #if VERBOSE:
    print("generated {0} macros from strontics list".format(generated_count))

    print("finished successfully!")


if __name__ == "__main__":
    main(sys.argv[1:])
