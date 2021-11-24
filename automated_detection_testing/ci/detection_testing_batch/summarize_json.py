import json
from collections import OrderedDict
import argparse
import sys
import json
def outputResultsJSON(output_filename:str, data:list[dict], baseline:OrderedDict)->bool:
    success = True
    try:
        test_count = len(data)
        #Passed
        pass_count = len([x for x in data if x['success'] == True])
        
        #A failure or an error
        fail_only_count = len([x for x in data if x['success'] == False])
        
        #An error (every error is also a failure)
        fail_and_error_count = len([x for x in data if x['error'] == True])
        
        #A failure without an error
        fail_without_error_count = len([x for x in data if x['success'] == False and x['error'] == False])
        
        #This number should always be zero...
        error_and_success_count = len([x for x in data if x['success'] == True and x['error'] == True])
        if error_and_success_count > 0:
            print("Error - a test was successful, but also included an error. This should be impossible.",file=sys.stderr)
            success = False
            
        if test_count != (pass_count + fail_only_count):
            print("Error - the total tests [%d] does not equal the pass[%d]/fails[%d]"%(test_count, pass_count,fail_only_count))
            success=False

        if fail_only_count > 0:
            result = "FAIL for %d detections"%(fail_only_count)
            success = False
        else:
            result = "PASS for all %d detections"%(pass_count)

        summary={"TOTAL_TESTS": test_count, "TESTS_PASSED": pass_count, 
                 "TOTAL_FAILURES": fail_only_count, "FAIL_ONLY": fail_without_error_count, 
                 "FAIL_AND_ERROR":fail_and_error_count }

        with open(output_filename, "w") as jsonFile:
            json.dump({'summary':summary, 'baseline': baseline, 'results':data}, jsonFile, indent="   ")
    except Exception as e:
        print("There was an error generating [%s]: [%s]"%(output_filename, str(e)),file=sys.stderr)
        raise(e)
        #success = False
        #return success, False

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

    test_pass = outputResultsJSON(args.output_filename, all_data['results'], all_data['baseline'])
    print("Successfully summarized [%d] detections"%(len(all_data['results'])))
    if not test_pass:
        print("Result: FAIL")
        sys.exit(1)
    else:
        print("Result: PASS!")
        sys.exit(0)

    
except Exception as e:
    print("Error writing the summary file: [%s].\n\tQuitting..."%(str(e)))
    sys.exit(1)



    


