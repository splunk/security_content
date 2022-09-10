
import re
import shutil

#import ansible_runner

from modules.DataManipulation import DataManipulation
from modules import utils
from modules import splunk_sdk


from os.path import relpath
from tempfile import mkdtemp, mkstemp

import splunklib.client as client
from modules.test_objects import Detection, Test, Baseline, Result, AttackData




def get_service(splunk_ip:str, splunk_port:int, splunk_password:str):

    try:
        service = client.connect(
            host=splunk_ip,
            port=splunk_port,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        raise(Exception("Unable to connect to Splunk instance: " + str(e)))
    return service


def execute_tests(splunk_ip:str, splunk_port:int, splunk_password:str, tests:list[Test], attack_data_folder:str, wait_on_failure:bool, wait_on_completion:bool)->bool:
        
        success = True
        for test in tests:
            try:
                #Run all the tests, even if the test fails.  We still want to get the results of failed tests
                result = execute_test(splunk_ip, splunk_port, splunk_password, test, attack_data_folder, wait_on_failure, wait_on_completion)
                #And together the result of the test so that if any one test fails, it causes this function to return False                
                success &= result
            except Exception as e:
                raise(Exception(f"Unknown error executing test: {str(e)}"))
        return success
            




def format_test_result(job_result:dict, testName:str, fileName:str, logic:bool=False, noise:bool=False)->dict:
    testResult = {
        "name": testName,
        "file": fileName,
        "logic": logic,
        "noise": noise,
    }


    if 'status' in job_result:
        #Test failed, no need for further processing
        testResult['status'] = job_result['status']
    
    
        
    else:
       #Mark whether or not the test passed
        if job_result['eventCount'] == 1:
            testResult["status"] = True
        else:
            testResult["status"] = False


    JOB_FIELDS = ["runDuration", "scanCount", "eventCount", "resultCount", "performance", "search", "message"]
    #Populate with all the fields we want to collect
    for job_field in JOB_FIELDS:
        if job_field in job_result:
            testResult[job_field] = job_result.get(job_field, None)
    
    return testResult

def execute_baselines(splunk_ip:str, splunk_port:int, splunk_password:str, baselines:list[Baseline])->bool:
    baseline_results = []
    for baseline in baselines:
        if execute_baseline(splunk_ip, splunk_port, splunk_password, baseline) is not True:
            return False
    
    #All the baselines succeeded (or there were no baselines to execute)
    return True

def execute_baseline(splunk_ip:str, splunk_port:int, splunk_password:str, baseline:Baseline)->bool:
    
    baseline.result = splunk_sdk.test_detection_search(splunk_ip, splunk_port, splunk_password, 
                                              baseline.baseline.search, baseline.pass_condition, 
                                              baseline.name, baseline.earliest_time, baseline.latest_time)
    
    return baseline.result.success
    
def execute_test(splunk_ip:str, splunk_port:int, splunk_password:str, test:Test, attack_data_folder:str, wait_on_failure:bool, wait_on_completion:bool)->bool:
    print(f"\tExecuting test {test.name}")
    
    #replay all of the attack data
    test_indices = replay_attack_data_files(splunk_ip, splunk_port, splunk_password, test.attack_data, attack_data_folder)

    
    
    #Run the baseline(s) if they exist for this test
    if execute_baselines(splunk_ip, splunk_port, splunk_password, test.baselines) is not True:
        #One of the baselines failed. No sense in running the real test
        test.result = Result(generated_exception={'message':"Baseline(s) failed"})
        
        
    else:
        test.result = splunk_sdk.test_detection_search(splunk_ip, splunk_port, splunk_password, test.detectionFile.search, test.pass_condition, test.name, test.earliest_time, test.latest_time)
        
 
    if wait_on_completion or (wait_on_failure and (test.result.success == False)):
        # The user wants to debug the test
        message_template = "\n\n\n****SEARCH {status} : Allowing time to debug search/data****\nPress ENTER to continue..."
        if test.result.success == False:
            # The test failed
            formatted_message = message_template.format(status="FAILURE")
            
        else:
            #The test passed 
            formatted_message = message_template.format(status="SUCCESS")

        #Just use this to pause on input, we don't do anything with the response
        print(f"DETECTION FILE: {test.detectionFile.path}")
        print(f"DETECTION SEARCH: {test.result.search}")
        print(test.detectionFile.search)
        _ = input(formatted_message)

    splunk_sdk.delete_attack_data(splunk_ip, splunk_password, splunk_port, indices = test_indices)
    
    #Return whether the test passed or failed
    return test.result.success

def replay_attack_data_file(splunk_ip:str, splunk_port:int, splunk_password:str, attackData:AttackData, attack_data_folder:str)->str:
    """Function to replay a single attack data file. Any exceptions generated during executing
    are intentionally not caught so that they can be caught by the caller.

    Args:
        splunk_ip (str): ip address of the splunk server to target
        splunk_port (int): port of the splunk server API
        splunk_password (str): password to the splunk server
        attack_data_file (dict): a dict containing information about the attack data file
        attack_data_folder (str): The folder for downloaded or copied attack data to reside

    Returns:
        str: index that the attack data has been replayed into on the splunk server
    """
    #Get the index we should replay the data into
    print("replaying single attack data file")
    
    descriptor, data_file = mkstemp(prefix="ATTACK_DATA_FILE_", dir=attack_data_folder)
    if not attackData.data.startswith("https://"):
        #raise(Exception(f"Attack Data File {attack_data_file['file_name']} does not start with 'https://'. "  
        #                 "In the future, we will add support for non https:// hosted files, such as local files or other files. But today this is an error."))
        
        #We need to do this because if we are working from a file, we can't overwrite/modify the original during a test. We must keep it intact.
        try:
            print(f"copy from {attackData.data}-->{data_file}")
            shutil.copyfile(attackData.data, data_file)
        except Exception as e:
            raise(Exception(f"Unable to copy local attack data file {attackData.data} - {str(e)}"))
        
    
    else:
        #Download the file
        print(f"download from {attackData.data}-->{data_file}")
        utils.download_file_from_http(attackData.data, data_file)
    
    # Update timestamps before replay
    if attackData.update_timestamp:
        data_manipulation = DataManipulation()
        print(f"ABSOLUTE FILE PATH: {data_file}")
        import os
        relpath = os.path.relpath(data_file)
        print(f"RELATIVE FILE PATH: {relpath}")
        data_manipulation.manipulate_timestamp(relpath, attackData.sourcetype,attackData.source)    

    #Get an session from the API
    service = get_service(splunk_ip, splunk_port, splunk_password)
    #Get the index we will be uploading to
    upload_index = service.indexes[attackData.index]
        
    #Upload the data
    print(f"the data file is: {data_file}")
    with open(data_file, 'rb') as target:
        upload_index.submit(target.read(), sourcetype=attackData.sourcetype, source=attackData.source, host=splunk_sdk.DEFAULT_EVENT_HOST)

    #Wait for the indexing to finish
    if not splunk_sdk.wait_for_indexing_to_complete(splunk_ip, splunk_port, splunk_password, attackData.sourcetype, upload_index):
        raise Exception("There was an error waiting for indexing to complete.")
    
    print('done waiting')
    #Return the name of the index that we uploaded to
    return attackData.index




    

def replay_attack_data_files(splunk_ip:str, splunk_port:int, splunk_password:str, attackDataObjects:list[AttackData], attack_data_folder:str)->set[str]:
    """Replay all attack data files into a splunk server as part of testing a detection. Note that this does not catch
    any exceptions, they should be handled by the caller

    Args:
        splunk_ip (str): ip address of the splunk server to target
        splunk_port (int): port of the splunk server API
        splunk_password (str): password to the splunk server
        attack_data_files (list[dict]): A list of dicts containing information about the attack data file
        attack_data_folder (str): The folder for downloaded or copied attack data to reside
    """
    print('replaying all attack data')
    test_indices = set()
    for attack_data_file in attackDataObjects:
        try:
            test_indices.add(replay_attack_data_file(splunk_ip, splunk_port, splunk_password, attack_data_file, attack_data_folder))
        except Exception as e:
            raise(Exception(f"Error replaying attack data file {attack_data_file.data}: {str(e)}"))
    return test_indices

def test_detection(splunk_ip:str, splunk_port:int, splunk_password:str, test_file:Detection, attack_data_root_folder, wait_on_failure:bool, wait_on_completion:bool)->bool:
    

    abs_folder_path = mkdtemp(prefix="DATA_", dir=attack_data_root_folder)
    success = execute_tests(splunk_ip, splunk_port, splunk_password, test_file.testFile.tests, abs_folder_path, wait_on_failure, wait_on_completion)
    #Delete the folder and all of the data inside of it
    #shutil.rmtree(abs_folder_path)
    return success






