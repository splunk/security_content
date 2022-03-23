import json
from collections import OrderedDict
import argparse
import sys
import json
from modules import validate_args
import os.path
from operator import itemgetter
import copy

def outputResultsJSON(output_filename:str, data:list[dict], baseline:OrderedDict, 
                      failure_manifest_filename = "detection_failure_manifest.json", 
                      output_folder:str="", summarization_reproduce_failure_config:dict={})->tuple[bool,int,int,int,int]:
    success = True
    
    try:
        test_count = len(data)
        #Passed
        pass_count = len([x for x in data if x['success'] == True])
        
        
        #A failure or an error
        fail_count = len([x for x in data if x['success'] == False])
        
        #An error (every error is also a failure)
        fail_and_error_count = len([x for x in data if x['error'] == True])
        
        #A failure without an error
        fail_without_error_count = len([x for x in data if x['success'] == False and x['error'] == False])
        
        #This number should always be zero...
        error_and_success_count = len([x for x in data if x['success'] == True and x['error'] == True])
        if error_and_success_count > 0:
            print("Error - a test was successful, but also included an error. This should be impossible.",file=sys.stderr)
            success = False
            
        if test_count != (pass_count + fail_count):
            print("Error - the total tests [%d] does not equal the pass[%d]/fails[%d]"%(test_count, pass_count,fail_count))
            success=False

        if fail_count > 0:
            result = "FAIL for %d detections"%(fail_count)
            success = False
        else:
            result = "PASS for all %d detections"%(pass_count)


        summary={"TOTAL_TESTS": test_count, "TESTS_PASSED": pass_count, 
                 "TOTAL_FAILURES": fail_count, "FAIL_ONLY": fail_without_error_count, 
                 "PASS_RATE": calculate_pass_rate(pass_count, test_count),
                 "FAIL_AND_ERROR":fail_and_error_count }

        data_sorted = sorted(data, key = lambda k: (-k['error'], k['success'], k['detection_file']))
        with open(os.path.join(output_folder,output_filename), "w") as jsonFile:
            json.dump({'summary':summary, 'baseline': baseline, 'results':data_sorted}, jsonFile, indent="    ")
        
        
        #Generate a failure that the user can download to reproduce and test ONLY the failures locally.
        #This makes it easy to test and debug ONLY those that failed.  No need to test the ones
        #that succeeded!
        
        
        fail_list = [os.path.join("security_content/detections",x['detection_file'] ) for x in data_sorted if x['success'] == False]

        if len(fail_list) > 0:
            print("FAILURES:")
            for failed_test in fail_list:
                print(f"\t{failed_test}")
            failures_test_override = copy.deepcopy(summarization_reproduce_failure_config)
            #Force all tests to be interactive, even if they don't fail (because they failed on this test)
            failures_test_override.update({"detections_list": fail_list, "no_interactive_failure":False, "interactive": True,
                                    "num_containers":1, "branch": baseline["branch"], "commit_hash":baseline["commit_hash"], 
                                    "mode":"selected", "show_splunk_app_password": True})
            with open(os.path.join(output_folder,failure_manifest_filename),"w") as failures:
                validate_args.validate_and_write(failures_test_override, failures)
    except Exception as e:
        print("There was an error generating [%s]: [%s]"%(output_filename, str(e)),file=sys.stderr)
        print(data)
        raise(e)
        #success = False
        #return success, False

    #note that total failures is fail_count, fail_and_error count is JUST errors (and every error is also a failure)
    return success, test_count, pass_count, fail_count, fail_and_error_count

def calculate_pass_rate(pass_count:int, test_count:int)->float:
    if test_count == 0:
        #Assume this means 100% pass rate to avoid divide by zero
        pass_rate = 1
    else:
        pass_rate = pass_count / test_count
    return pass_rate

def print_summary(test_count: int, pass_count:int, fail_count:int, error_count:int)->None:
    
    print("Summary:"\
            f"\n\tTotal Tests: {test_count}"\
            f"\n\tTotal Pass : {pass_count}"\
            f"\n\tTotal Fail : {fail_count} ({error_count} of these were ERRORS))"\
            f"\n\tPass  Rate : {calculate_pass_rate(pass_count, test_count):.3f}")

def exit_with_status(test_pass:bool, test_count: int, pass_count:int, fail_count:int, error_count:int)->None:
    if not test_pass:
        print("Result: FAIL")
        #print("DURING TESTING, THIS WILL STILL EXIT WITH AN EXIT CODE OF 0 (SUCCESS) TO ALLOW THE WORKFLOW "
        #      "TO PASS AND CI/CD TO CONTINUE.  THIS WILL BE CHANGED IN A FUTURE VERSION.")
        #sys.exit(0)
        sys.exit(1)
    else:
        print("Result: PASS!")
        sys.exit(0)


def finish(test_pass:bool, test_count: int, pass_count:int, fail_count:int, error_count:int)->None:
    print_summary(test_count, pass_count, fail_count,error_count)
    exit_with_status(test_pass, test_count, pass_count, fail_count,error_count)

def main():
    parser = argparse.ArgumentParser(description="Results Merger")
    parser.add_argument('-f', '--files', type=argparse.FileType('r'), required=True, nargs='+', help="The json files you would like to combine into a single file")
    parser.add_argument('-o', '--output_filename', type=str, required=True, help="The name of the output file")
    args = parser.parse_args()

    all_data = OrderedDict()
    try:
        print("We will summarize the files: %s"%(str([f.name for f in args.files])))
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

        test_pass, test_count, pass_count, fail_count, error_count = outputResultsJSON(args.output_filename, all_data['results'], all_data['baseline'])
        finish(test_pass, test_count, pass_count, fail_count, error_count)
        
    except Exception as e:
        print("Error generating the summary file: [%s].\n\tQuitting..."%(str(e)))
        sys.exit(1)

if __name__=="__main__":
    main()


    


