
import re
import shutil
import json

#import ansible_runner

from modules.DataManipulation import DataManipulation
from modules import utils
from modules import splunk_sdk


from os.path import relpath
from tempfile import mkdtemp, mkstemp

import splunklib.client as client
from modules.test_objects import Detection, Test, Baseline, TestResult, AttackData


from typing import Union
import urllib.parse
from urllib3 import disable_warnings
import requests
import pathlib

import os

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


def execute_tests(splunk_ip:str, splunk_port:int, splunk_password:str, tests:list[Test], attack_data_folder:str, wait_on_failure:bool, wait_on_completion:bool, container)->bool:
    
    success = True
    for test in tests:
        try:
            #Run all the tests, even if the test fails.  We still want to get the results of failed tests
            result = execute_test(splunk_ip, splunk_port, splunk_password, test, attack_data_folder, wait_on_failure, wait_on_completion,container)
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

def execute_baselines(splunk_ip:str, splunk_port:int, splunk_password:str, baselines:list[Baseline]):
    for baseline in baselines:
        execute_baseline(splunk_ip, splunk_port, splunk_password, baseline)
    
    

def execute_baseline(splunk_ip:str, splunk_port:int, splunk_password:str, baseline:Baseline):
    
    baseline.result = splunk_sdk.test_detection_search(splunk_ip, splunk_port, splunk_password, 
                                              baseline.baseline.search, baseline.pass_condition, 
                                              baseline.name, baseline.earliest_time, baseline.latest_time)
    
    

def execute_test(splunk_ip:str, splunk_port:int, splunk_password:str, test:Test, attack_data_folder:str, wait_on_failure:bool, wait_on_completion:bool,container)->bool:
    
    print(f"\tExecuting test {test.name}")
    #replay all of the attack data
    test_indices = replay_attack_data_files(splunk_ip, splunk_port, splunk_password, test.attack_data, attack_data_folder,container)

    import timeit, time
    start = timeit.default_timer()
    MAX_TIME = 120
    sleep_base = 2
    sleep_exp = 0
    while True:
        sleeptime = sleep_base**sleep_exp
        sleep_exp += 1
        #print(f"Sleep for {sleeptime} for ingest") 
        time.sleep(sleeptime)
        #Run the baseline(s) if they exist for this test
        execute_baselines(splunk_ip, splunk_port, splunk_password, test.baselines)
        if test.error_in_baselines() is True:
            #One of the baselines failed. No sense in running the real test
            #Note that a baselines which fail is different than a baselines which didn't return some results!
            test.result = TestResult(generated_exception={'message':"Baseline(s) failed"})
        elif test.all_baselines_successful() is False:
            #go back and run the loop again - no sense in running the detection search if the baseline didn't work successfully
            test.result = TestResult(generated_exception={'message':"Detection search did not run - baselines(s) failed"})
            #we set this as exception false because we don't know for sure there is an issue - we could just
            #be waiting for data to be ingested for the baseline to fully run. However, we don't have the info
            #to fill in the rest of the fields, so we populate it like we populate the fields when there is a real exception
            test.result.exception = False 
            continue
            
        else:
            #baselines all worked (if they exist) so run the search
            test.result = splunk_sdk.test_detection_search(splunk_ip, splunk_port, splunk_password, test.detectionFile.search, test.pass_condition, test.name, test.earliest_time, test.latest_time)
        
        if test.result.success:
            #We were successful, no need to run again.
            break
        elif test.result.exception:
            #There was an exception, not just a failure to find what we're looking for. break 
            break
        elif timeit.default_timer() - start > MAX_TIME:
            break
        
 
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
        _ = input(formatted_message)

    splunk_sdk.delete_attack_data(splunk_ip, splunk_password, splunk_port, indices = test_indices)
    
    #Return whether the test passed or failed
    return test.result.success


def hec_raw_replay(base_url:str, token:str, filePath:pathlib.Path, index:str, 
                   source:Union[str,None]=None, sourcetype:Union[str,None]=None, 
                   host:Union[str,None]=None, channel:Union[str,None]=None, 
                   use_https:bool=True, port:int=8088, verify=False, 
                   path:str="services/collector/raw", wait_for_ack:bool=True):
    
    if verify is False:
        #need this, otherwise every request made with the requests module
        #and verify=False will print an error to the command line
        disable_warnings()


    #build the headers
    if token.startswith('Splunk '):
        headers = {"Authorization": token} 
    else:
        headers = {"Authorization": f"Splunk {token}"} #token must begin with 'Splunk 
    
    if channel is not None:
        headers['X-Splunk-Request-Channel'] = channel
    
    
    #Now build the URL parameters
    url_params_dict = {"index": index}
    if source is not None:
        url_params_dict['source'] = source 
    if sourcetype is not None:
        url_params_dict['sourcetype'] = sourcetype
    if host is not None:
        url_params_dict['host'] = host 
    
    
    if base_url.lower().startswith('http://') and use_https is True:
        raise(Exception(f"URL {base_url} begins with http://, but use_http is {use_https}. "\
                         "Unless you have modified the HTTP Event Collector Configuration, it is probably enabled for https only."))
    if base_url.lower().startswith('https://') and use_https is False:
        raise(Exception(f"URL {base_url} begins with https://, but use_http is {use_https}. "\
                         "Unless you have modified the HTTP Event Collector Configuration, it is probably enabled for https only."))
    
    if not (base_url.lower().startswith("http://") or base_url.lower().startswith('https://')):
        if use_https:
            prepend = "https://"
        else:
            prepend = "http://"
        old_url = base_url
        base_url = f"{prepend}{old_url}"
        #print(f"Warning, the URL you provided {old_url} does not start with http:// or https://.  We have added {prepend} to convert it into {base_url}")
    

    #Generate the full URL, including the host, the path, and the params.
    #We can be a lot smarter about this (and pulling the port from the url, checking 
    # for trailing /, etc, but we leave that for the future)
    url_with_path = urllib.parse.urljoin(f"{base_url}:{port}", path)
    with open(filePath,"rb") as datafile:
        rawData = datafile.read()

    try:
        res = requests.post(url_with_path,params=url_params_dict, data=rawData, allow_redirects = True, headers=headers, verify=verify)
        #print(f"POST Sent with return code: {res.status_code}")
        jsonResponse = json.loads(res.text)
        #print(res.status_code)
        #print(res.text)
        
    except Exception as e:
        raise(Exception(f"There was an exception in the post: {str(e)}"))
    

    if wait_for_ack:
        if channel is None:
            raise(Exception("HEC replay WAIT_FOR_ACK is enabled but CHANNEL is None. Channel must be supplied to wait on ack"))
        
        if "ackId" not in jsonResponse:
            raise(Exception(f"key 'ackID' not present in response from HEC server: {jsonResponse}"))
        ackId = jsonResponse['ackId']
        url_with_path = urllib.parse.urljoin(f"{base_url}:{port}", "services/collector/ack")
        import timeit, time
        start = timeit.default_timer()
        j = {"acks":[jsonResponse['ackId']]}
        while True:            
            try:
                
                res = requests.post(url_with_path, json=j, allow_redirects = True, headers=headers, verify=verify)
                #print(f"ACKID POST Sent with return code: {res.status_code}")
                jsonResponse = json.loads(res.text)
                #print(f"the type of ackid is {type(ackId)}")
                if 'acks' in jsonResponse and str(ackId) in jsonResponse['acks']:
                    if jsonResponse['acks'][str(ackId)] is True:
                        break
                    else:
                        #print("Waiting for ackId")

                        time.sleep(2)

                else:
                    print(url_with_path)
                    print(j)
                    print(headers)
                    raise(Exception(f"Proper ackID structure not found for ackID {ackId} in {jsonResponse}"))
            except Exception as e:
                raise(Exception(f"There was an exception in the post: {str(e)}"))
            




def replay_attack_data_file(splunk_ip:str, splunk_port:int, splunk_password:str, attackData:AttackData, attack_data_folder:str,container)->str:
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
    
    
    descriptor, data_file = mkstemp(prefix="ATTACK_DATA_FILE_", dir=attack_data_folder)
    if not (attackData.data.startswith("https://") or attackData.data.startswith("http://")):
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
        #We need to overwrite the file - mkstemp will create an empty file with the 
        #given name
        utils.download_file_from_http(attackData.data, data_file, overwrite_file=True) 
    
    # Update timestamps before replay
    if attackData.update_timestamp:
        data_manipulation = DataManipulation()
        relpath = os.path.relpath(data_file)
        data_manipulation.manipulate_timestamp(relpath, attackData.sourcetype,attackData.source)    

    #Get an session from the API
    service = get_service(splunk_ip, splunk_port, splunk_password)
    #Get the index we will be uploading to
    upload_index = service.indexes[attackData.index]
        
    #Upload the data
    hec_raw_replay(container.splunk_ip, container.tokenString, pathlib.Path(data_file), attackData.index, attackData.source, attackData.sourcetype, splunk_sdk.DEFAULT_EVENT_HOST, channel=container.channel, port=container.hec_port)
    

    #Wait for the indexing to finish
    #print("skip waiting for ingest since we have checked the ackid")
    #if not splunk_sdk.wait_for_indexing_to_complete(splunk_ip, splunk_port, splunk_password, attackData.sourcetype, upload_index):
    #    raise Exception("There was an error waiting for indexing to complete.")
    
    #print('done waiting')
    #Return the name of the index that we uploaded to
    return attackData.index




    

def replay_attack_data_files(splunk_ip:str, splunk_port:int, splunk_password:str, attackDataObjects:list[AttackData], attack_data_folder:str,container)->set[str]:
    """Replay all attack data files into a splunk server as part of testing a detection. Note that this does not catch
    any exceptions, they should be handled by the caller

    Args:
        splunk_ip (str): ip address of the splunk server to target
        splunk_port (int): port of the splunk server API
        splunk_password (str): password to the splunk server
        attack_data_files (list[dict]): A list of dicts containing information about the attack data file
        attack_data_folder (str): The folder for downloaded or copied attack data to reside
    """
    test_indices = set()
    for attack_data_file in attackDataObjects:
        try:
            test_indices.add(replay_attack_data_file(splunk_ip, splunk_port, splunk_password, attack_data_file, attack_data_folder,container))
        except Exception as e:
            raise(Exception(f"Error replaying attack data file {attack_data_file.data}: {str(e)}"))
    return test_indices


def test_detection(splunk_ip:str, splunk_port:int, splunk_password:str, detection:Detection, attack_data_root_folder, wait_on_failure:bool, wait_on_completion:bool,container)->bool:
    

    abs_folder_path = mkdtemp(prefix="DATA_", dir=attack_data_root_folder)
    success = execute_tests(splunk_ip, splunk_port, splunk_password, detection.testFile.tests, abs_folder_path, wait_on_failure, wait_on_completion, container)
    shutil.rmtree(abs_folder_path)
    detection.get_detection_result()
    #Delete the folder and all of the data inside of it
    #shutil.rmtree(abs_folder_path)
    return success






