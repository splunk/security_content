import json
from collections import OrderedDict
import argparse
import sys
import json
from modules import validate_args
import os.path
from operator import itemgetter
import copy

def outputResultsJSON(output_filename:str, data:list[dict], background:OrderedDict, 
                      failure_manifest_filename = "detection_failure_manifest.json", 
                      output_folder:str="", summarization_reproduce_failure_config:dict={})->dict:
    success = True
    
    try:
        #Summarize all of the detections
        detection_pass_count = 0
        detection_fail_count = 0
        test_pass_count = 0
        test_fail_count = 0
        test_logic_pass_count = 0
        test_logic_fail_count = 0
        test_noise_pass_count = 0
        test_noise_fail_count = 0
        
        
        #Summarize all of the tests
        for detection in data:
            if detection['success'] is True:
                detection_pass_count += 1
            else:
                detection_fail_count += 1
            
            if len(detection.get("tests",[])) == 0:
                print(f"Did not find a tests field in detection {detection['name']} or the length of the tests was 0.")
                continue
            for test in detection.get("tests",[]):
                if test['success'] is True:
                    test_pass_count += 1
                else:
                    test_fail_count += 1
                if test['logic'] is True:
                    test_logic_pass_count += 1
                else:
                    test_logic_fail_count += 1
                if test['noise'] is True:
                    test_noise_pass_count += 1
                else:
                    test_noise_fail_count += 1
        

        
        summary = {
        "detections": detection_pass_count + detection_fail_count,
        "detections_pass_count": detection_pass_count,
        "detections_fail_count": detection_fail_count,
        "detections_pass_rate": round(detection_pass_count / (detection_pass_count + detection_fail_count),3),
        "tests": test_pass_count + test_fail_count,
        "tests_pass_count": test_pass_count,
        "tests_fail_count": test_fail_count,
        "tests_pass_rate": round(test_pass_count / (test_pass_count + test_fail_count),3),
        "tests_logic": test_logic_pass_count + test_logic_fail_count,
        "tests_logic_pass_count": test_logic_pass_count,
        "tests_logic_fail_count": test_logic_fail_count,
        "tests_logic_pass_rate": round(test_logic_pass_count / (test_logic_pass_count + test_logic_fail_count),3),
        "tests_noise": test_noise_pass_count + test_noise_fail_count,
        "tests_noise_pass_count": test_noise_pass_count,
        "tests_noise_fail_count": test_noise_fail_count,
        "tests_noise_pass_rate": round(test_noise_pass_count / (test_noise_pass_count + test_noise_fail_count),3)
        }

        data_sorted = sorted(data, key = lambda k: (k['success'], k['path']))
        with open(os.path.join(output_folder,output_filename), "w") as jsonFile:
            json.dump({'summary':summary, 'background': background, 'detections':data_sorted}, jsonFile, indent="    ")
        
        return summary
        
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

def print_summary(summary:dict)->None:
    
    print("Summary:"\
            f"\n\tDetections      : {summary['detections']}"\
            f"\n\tDetections Pass : {summary['detections_pass_count']}"\
            f"\n\tDetections Fail : {summary['detections_fail_count']}"\
            f"\n\tDetections Rate : {summary['detections_pass_rate']}"\
            f"\n\tTests           : {summary['tests']}"\
            f"\n\tTests Pass      : {summary['tests_pass_count']}"\
            f"\n\tTests Fail      : {summary['tests_fail_count']}"\
            f"\n\tTests Rate      : {summary['tests_pass_rate']}")

def exit_with_status(summary:dict)->None:
    if summary['tests_failures'] > 0:
        print("Result: FAIL")
        #print("DURING TESTING, THIS WILL STILL EXIT WITH AN EXIT CODE OF 0 (SUCCESS) TO ALLOW THE WORKFLOW "
        #      "TO PASS AND CI/CD TO CONTINUE.  THIS WILL BE CHANGED IN A FUTURE VERSION.")
        #sys.exit(0)
        sys.exit(1)
    else:
        print("Result: PASS!")
        sys.exit(0)


def finish(summary)->None:
    print_summary(summary)
    exit_with_status(summary)

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
            if 'background' in all_data:
                #everything has the same baseline, only need to do it once
                pass
            else:
                all_data['background'] = data['background']
            if 'detections' in all_data:
                #this is a list of dictionaries, so add to it
                all_data['detections'].extend(data['detections'])
            else:
                all_data['detections'] = data['detections']

        summary = outputResultsJSON(args.output_filename, all_data['detections'], all_data['background'])
        finish(summary)
        
    except Exception as e:
        print("Error generating the summary file: [%s].\n\tQuitting..."%(str(e)))
        sys.exit(1)

if __name__=="__main__":
    main()


    


