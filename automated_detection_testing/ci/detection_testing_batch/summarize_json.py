import json
from collections import OrderedDict
import argparse
import sys
import json
def outputResultsJSON(output_filename:str, data:list[dict], baseline:OrderedDict)->bool:
    success = True
    try:
        with open(output_filename, "w") as jsonFile:
            json.dump({'baseline': baseline, 'results':data}, jsonFile, indent="   ")
    except Exception as e:
        print("There was an error generating [%s]: [%s]"%(output_filename, str(e)))
        success = False
    return success



parser = argparse.ArgumentParser(description="Results Merger")
parser.add_argument('-f', '--files', type=argparse.FileType('r'), required=True, nargs='+', help="The json files you would like to combine into a single file")
parser.add_argument('-o', '--output_filename', type=str, required=True, help="The name of the output file")
args = parser.parse_args()

all_data = OrderedDict()
try:
    for f in args.files:
        if not f.name.endswith('.json'):
            print("Error: passed in file must end in .json - you passed in [%s].\n\tQuitting..."%(f.name))
            sys.exit(1)
        data = json.loads(f.read())
        if 'baseline' in all_data:
            #everything has the same baseline, only need to do it once
            pass
        else:
            all_data['baseline'] = data['baseline']
        if 'results' in all_data:
            #this is a list of dictionaries, so add to it
            all_data['results'].extend(data['results'])
        else:
            all_data['results'] = data['results']

    outputResultsJSON(args.output_filename, all_data['results'], all_data['baseline'])
    print("Successfully summarized [%d] detections!"%(len(all_data['results'])))
except Exception as e:
    print("Error writing the summary file: [%s].\n\tQuitting..."%(str(e)))
    sys.exit(1)



    


