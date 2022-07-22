import copy
import csv
import datetime
import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
import timeit
from collections import OrderedDict
from typing import Union

import psutil
import summarize_json


class TestDriver:
    def __init__(self, tests:list[str], num_containers:int, summarization_reproduce_failure_config:dict):
        #Create the queue and enque all of the tests
        self.testing_queue = queue.Queue()
        for test in tests:
            self.testing_queue.put(test)
        
        self.total_number_of_tests = self.testing_queue.qsize()
        #Creates a lock that will be used to synchronize access to this object
        self.lock = threading.Lock()
        self.start_time = timeit.default_timer()
        self.failures = []
        self.successes = []
        self.errors = []
        self.container_ready_time = None
        
        #No containers have failed
        self.container_failure = False

        #Just make a random folder to store attack data that we donwload
        self.attack_data_root_folder = tempfile.mkdtemp(prefix="attack_data_", dir=os.getcwd())
        print("Attack data for this run will be stored at: [%s]"%(self.attack_data_root_folder))
        
        #Not used right now, but we will keep it around for a bit in case we want to use it again
        self.start_barrier = threading.Barrier(num_containers)

        #The config that will be used for writing out the error config reproduction fiel
        self.summarization_reproduce_failure_config = copy.deepcopy(summarization_reproduce_failure_config)


        #According to the docs:
        # Warning the first time this function is called with interval = 0.0 or None it will return a meaningless 0.0 value which you are supposed to ignore.
        # We call this exactly once here to prime for future calls and throw away the result
        cpu_info = psutil.cpu_times_percent(percpu=False)
            

    def checkContainerFailure(self)->bool:
        
        self.lock.acquire()
        
        try:
            result = self.container_failure
        finally:
            self.lock.release()
        
        
        
        return result
        

    def containerFailure(self)->None:
        self.lock.acquire()
        try:
            self.container_failure = True
        finally:
            self.lock.release()
        
    def checkIfTestsRemain(self):
        failure = self.checkContainerFailure()
        if failure:
            #Just return None, don't continue testing if a container crashed
            #Indicate there are no tests remaining
            return False
        
        try:
            #This call isn't reliable according to documentation, but can save us some time.
            #Err on the side of caution
            return not self.testing_queue.empty()
        except Exception as e:
            print("Error determinging if testing queue was empty.  Return False and try to get something.",file=sys.stderr)
            return True
        

    def getTest(self)-> Union[str,None]:
        
        failure = self.checkContainerFailure()
        
        

        if failure:
            #Just return None, don't continue testing if a container crashed
            return None

        try:
            return self.testing_queue.get(block=False)
        except Exception as e:
            return None
        
    def addSuccess(self, result:dict, duration_string:str)->None:
        print("Test PASSED: [%s --> %s] in %s"%(result['detection_name'], result['detection_file'], duration_string))
        self.lock.acquire()
        try:
            self.successes.append(result)
        finally:
            self.lock.release()
        

    def addFailure(self, result:dict, duration_string:str)->None:
        print("Test FAILED: [%s --> %s] in %s"%(result['detection_name'], result['detection_file'], duration_string))
        self.lock.acquire()
        try:
            self.failures.append(result)
        finally:
            self.lock.release()

    def addError(self, result:dict, duration_string:str)->None:
        #Make sure that even errors have all of the required fields.
        for required_field in ['search_string', 'diskUsage','runDuration', 'detection_name', 'scanCount', 'detection_error', 'detection_file']:
            if required_field not in result:
                result[required_field] = ""
        if  'error' not in result:
            result['error'] = True
        if  'success' not in result:
            result['success'] = False
        print("Test ERROR: [%s --> %s] in %s"%(result['detection_name'], result['detection_file'], duration_string))
        self.lock.acquire()
        try:
            self.errors.append(result)
        finally:
            self.lock.release()
    

    def outputResultsCSV(self, field_names:list[str], output_filename:str, data:list[dict], baseline:OrderedDict)->bool:
        success = True

        print("Generating %s..."%(output_filename), end='')
        self.lock.acquire()
        
        try:                        
            with open(output_filename, 'w') as csvfile:
                header_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
                for key in baseline:
                    #Very basic support for pretty pritning dicts. Doesn't handle more than 1 nested dict
                    if type(baseline[key]) is OrderedDict:
                        header_writer.writerow([key, "-"])
                        for nestedkey in baseline[key]:
                            header_writer.writerow([nestedkey, baseline[key][nestedkey]])
                    #Basic support for 1 layer nested list. Doesn't handle more than 1.
                    elif type(baseline[key]) is list and len(baseline[key])>0:
                        header_writer.writerow([key, baseline[key][0]])
                        for i in range(1,len(baseline[key])):
                            header_writer.writerow(['-', baseline[key][i]])
                        
                    else:
                        header_writer.writerow([key, baseline[key]])
                header_writer.writerow(['',''])
                csv_writer = csv.DictWriter(csvfile, fieldnames=field_names)
                csv_writer.writeheader()
                for row in data:
                    csv_writer.writerow(row)
            print("Done with [%d] detections"%(len(data)))

        except Exception as e:
            print("Failure writing to CSV file for [%s]:"%(output_filename, str(e)))
            success = False

        finally:
            self.lock.release()

        return success

    def outputResultsJSON(self, field_names:list[str], output_filename:str, data:list[dict], baseline:OrderedDict)->bool:
        success = True
        try:
            with open(output_filename, "w") as jsonFile:
                json.dump({'baseline': baseline, 'results':data}, jsonFile, indent="   ")
        except Exception as e:
            print("There was an error generating [%s]: [%s]"%(output_filename, str(e)))
            success = False
        return success
        
    def outputResultsFile(self, field_names:list[str], output_filename:str, data:list[dict], baseline:OrderedDict, output_json:bool=True, output_csv:bool=True)->bool:
        success = True
        if output_csv:
            success |= self.outputResultsCSV(field_names, output_filename + ".csv", data, baseline)
        if output_json:
            success |= self.outputResultsJSON(field_names, output_filename + ".json", data, baseline)
        return success
        

    def outputResultsFiles(self, baseline:OrderedDict, fields:list[str]=['detection_name', 'detection_file','runDuration','diskUsage', 'search_string', 'error', 'success', 'scanCount', 'detection_error'])->bool:
        results_directory = "test_results"
        try:
            shutil.rmtree(results_directory,ignore_errors=True)
            os.mkdir(results_directory)
        except Exception as e:
            print("There was an error removing the results directory [%s]: [%s].\n\t We will try to continue output anyway."%(results_directory, str(e)))


        res = self.outputResultsFile(fields,os.path.join(results_directory, "success"), self.successes, baseline)
        res |= self.outputResultsFile(fields, os.path.join(results_directory, "failure"), self.failures, baseline)
        res |= self.outputResultsFile(fields, os.path.join(results_directory, "error"), self.errors, baseline)
        combined_data = self.successes + self.failures + self.errors
        res |= self.outputResultsFile(fields, os.path.join(results_directory, "combined"), combined_data, baseline)
        
        try:
            success, test_count,pass_count,fail_count,error_count = \
                summarize_json.outputResultsJSON("summary.json", combined_data, 
                                                 baseline, output_folder=results_directory, 
                                                 summarization_reproduce_failure_config=self.summarization_reproduce_failure_config)
            summarize_json.print_summary(test_count, pass_count, fail_count, error_count)
            res |= success
        except Exception as e:
            print("Failure writing the summary file: [%s]"%str(e),file=sys.stderr)
            res = False

        return res

    def finish(self, baseline:OrderedDict):
        self.cleanup()
        success = True
        if self.outputResultsFiles(baseline) == False:
            print("There was an error generating one or more of the output files. "\
                  "Check the logs for details.",file=sys.stderr)
            success = False
        

        if self.checkContainerFailure():
            print("One or more containers crashed or the test was HALTED early, so testing did not complete successfully. We wrote out all the results that we could")
            return False
        else:
            return success

        

    def cleanup(self):
        self.lock.acquire()
        try:
            print("Removing all attack data that was downloaded during this test at: [%s]"%(self.attack_data_root_folder))
            shutil.rmtree(self.attack_data_root_folder)
            print("Successfully removed all attack data")
        finally:
            self.lock.release()

    def get_system_stats(self)->str:
        
        bytes_per_GB = 1024 * 1024 * 1024
        cpu_info = psutil.cpu_times_percent(percpu=False)
        memory_info = psutil.virtual_memory()
        disk_usage_info = psutil.disk_usage('/')

        #macOS is really weird about disk usage.... so to get free space we use TOTAL-FREE = USED instead of just USED
        corrected_used_space = disk_usage_info.total - disk_usage_info.free

        cpu_info_string =        "Total CPU Usage   : %d%% (%d CPUs)"%(100 - cpu_info.idle, psutil.cpu_count(logical=False))
        memory_info_string =     "Total Memory Usage: %0.1fGB USED / %0.1fGB TOTAL"%((memory_info.total - memory_info.available) / bytes_per_GB, memory_info.total / bytes_per_GB)
        disk_usage_info_string = "Total Disk Usage  : %0.1fGB USED / %0.1fGB TOTAL"%(corrected_used_space / bytes_per_GB, disk_usage_info.total / bytes_per_GB)
        
        return "System Information:\n\t%s\n\t%s\n\t%s"%(cpu_info_string, memory_info_string, disk_usage_info_string)


    def summarize(self,testing_currently_active:bool=False)->bool:
        self.lock.acquire()
        try:
        
            #Get a summary of some system stats
            system_stats=self.get_system_stats()
            
            current_time = timeit.default_timer()
            
            

            if not testing_currently_active:
                #Testing has not started yet. We are setting up containers
                print("***********PROGRESS UPDATE***********\n"\
                      "\tWaiting for container setup: %s\n\t%s\n"%(datetime.timedelta(seconds=current_time - self.start_time),system_stats))
            else:
                
                if self.container_ready_time is None:
                    #This is the first status update since container setup has completed.  Get the current time.
                    #This makes our remaining time estimates better since that estimate should not involve
                    #the container setup time  
                    print("SETTING THE CONTAINER READY TIME!")
                    
                    self.container_ready_time = current_time

                numberOfCompletedTests = len(self.successes) + len(self.failures) + len(self.errors)
                remaining_tests = self.testing_queue.qsize()         
                testsCurrentlyRunning = self.total_number_of_tests - remaining_tests - numberOfCompletedTests
                total_execution_time_seconds = round(current_time - self.start_time)

                test_execution_time_seconds = current_time - self.container_ready_time
                
                
                if numberOfCompletedTests == 0 or test_execution_time_seconds == 0:
                    estimated_seconds_to_finish_all_tests = "UNKNOWN"
                    estimated_completion_time_string = "UNKNOWN"
                    average_time_per_test_string = "UNKNOWN"
                else:
                    average_time_per_test = test_execution_time_seconds / numberOfCompletedTests
                    average_time_per_test_string = datetime.timedelta(seconds=round(test_execution_time_seconds/numberOfCompletedTests))
                    #divide testsCurrentlyRunning by 2.0 because, on average, each running test will be 50% completed
                    estimated_seconds_to_finish_all_tests = round(average_time_per_test * (remaining_tests + testsCurrentlyRunning/2.0))
                    estimated_completion_time_string = datetime.timedelta(seconds=estimated_seconds_to_finish_all_tests)
                    
                

            
                print(f"***********PROGRESS UPDATE***********\n"\
                f"\tElapsed Time               : {datetime.timedelta(seconds=total_execution_time_seconds)}\n"\
                f"\tTest Execution Time        : {datetime.timedelta(seconds=round(test_execution_time_seconds))}\n"\
                f"\tEstimated Remaining Time   : {estimated_completion_time_string}\n"\
                f"\tTests to run               : {remaining_tests}\n"\
                f"\tAverage Time Per Test      : {average_time_per_test_string}\n",
                f"\tTests currently running    : {testsCurrentlyRunning}\n"\
                f"\tTests completed            : {numberOfCompletedTests}\n"\
                f"\t\tSuccess : {len(self.successes)}\n"\
                f"\t\tFailure : {len(self.failures)}\n"\
                f"\t\tError   : {len(self.errors)}\n"\
                f"\t{system_stats}\n")

        except Exception as e:
            print("Error in printing execution summary: [%s]"%(str(e)))
        finally:
            self.lock.release()
            
        
        #Return true while there are tests remaining
        completed_tests = len(self.successes) + len(self.failures) + len(self.errors)
        remaining_tests = self.total_number_of_tests - completed_tests
        return remaining_tests > 0
                
        
        
    def addResult(self, result:dict, duration_string:str)->None:
        try:
            if result['detection_result']['error'] is True:
                self.addError(result['detection_result'], duration_string = duration_string)
            elif result['detection_result']['success'] is False:
                #This is actually a failure of the detection, not an error. Naming is confusiong
                self.addFailure(result['detection_result'], duration_string = duration_string)
            elif result['detection_result']['success'] is True:
                self.addSuccess(result['detection_result'], duration_string = duration_string)
        except Exception as e:
            #Neither a success or a failure, so add the object to the failures queue
            print('"There was an error adding the result: [%s]'%(str(e)))
            self.addError({'detection_file':"Unknown File", "detection_error":str(result)})

