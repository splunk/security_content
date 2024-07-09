"""
A simple script formatting test_results/summary.yml to display on github actions
"""

import yaml
import re
import os

def main():

    # Define the path to the YAML file
    #yaml_file_path = 'test_results/summary.yml'
    yaml_file_path = '/home/runner/work/security_content/security_content/test_results/summary.yml'
   
    # Check if the YAML file exists
    if not os.path.exists(yaml_file_path):
        print(f"Error: The file {yaml_file_path} does not exist.")
        exit(1)  # Exit with an error code

    # Load the YAML file
    with open(yaml_file_path, 'r') as file:
        data = yaml.safe_load(file)
    
    # Extract total_fail value and debug print it
    total_fail = data['summary']['total_fail']
    print("\033[1mDownload the job artifacts of this run and view complete summary in test_results/summary.yml for troubleshooting failures.\n\033[0m") 
    print(f"Extracted total_fail: [{total_fail}]\n")
    
    # Print all unit test details first
    print("Unit Test Details:\n")
    print(f"{'Name':<80} | {'Status':<6} | {'Test Type':<10} | {'Exception':<50}")
    print(f"{'----':<80} | {'------':<6} | {'---------':<10} | {'---------':<50}")
    for detection in data['tested_detections']:
        for test in detection['tests']:
            if test['test_type'].strip() == "unit":  # Check if the test type is "unit"
                name = detection['name'].strip()
                status = 'PASS' if test['success'] else 'FAIL'
                test_type = test['test_type'].strip()
                exception = test.get('exception', 'N/A')  # Get exception if exists, else 'N/A'
                if status == 'FAIL':
                    print(f"{name:<80} | {status:<6} | {test_type:<10} | {exception:<50}")
                else:
                    print(f"{name:<80} | {status:<6} | {test_type:<10} | {'-':<50}")

    # Check if total_fail is a valid integer and greater than or equal to one
    if re.match(r'^[0-9]+$', str(total_fail)) and int(total_fail) >= 1:
        # Print the message in bold
        print("CI Failure: There are failed tests.\n")
    else:
        print("CI Success: No failed tests.\n\n")
        
if __name__ == "__main__":
    main()