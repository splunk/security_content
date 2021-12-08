from collections import OrderedDict
import csv
import datetime
import json
import os
import queue
import shutil
import tempfile
import threading
import time
import timeit
from typing import Union
import sys

class TestDriver:
    def __init__(self, tests:list[str], num_containers:int):
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
        self.start_barrier = threading.Barrier(num_containers)


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
        

    def getTest(self)-> Union[str,None]:
        
        failure = self.checkContainerFailure()
        
        

        if failure:
            #Just return None, don't continue testing if a container crashed
            return None

        try:
            return self.testing_queue.get(block=False)
        except Exception as e:
            print("Testing queue empty!")
            return None
        
    def addSuccess(self, result:dict)->None:
        print("Test PASSED for detection: [%s --> %s"%(result['detection_name'], result['detection_file']))
        self.lock.acquire()
        try:
            self.successes.append(result)
        finally:
            self.lock.release()
        

    def addFailure(self, result:dict)->None:
        print("Test FAILED for detection: [%s --> %s"%(result['detection_name'], result['detection_file']))
        self.lock.acquire()
        try:
            self.failures.append(result)
        finally:
            self.lock.release()

    def addError(self, detection:dict)->None:
        #Make sure that even errors have all of the required fields.
        for required_field in ['search_string', 'diskUsage','runDuration', 'detection_name', 'scanCount']:
            if required_field not in detection:
                detection[required_field] = ""
        if  'error' not in detection:
            detection['error'] = True
        if  'success' not in detection:
            detection['success'] = False

        self.lock.acquire()
        try:
            self.errors.append(detection)
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
        res = self.outputResultsFile(fields,"success", self.successes, baseline)
        res |= self.outputResultsFile(fields, "failure", self.failures, baseline)
        res |= self.outputResultsFile(fields, "error", self.errors, baseline)
        res |= self.outputResultsFile(fields, "combined", self.successes + self.failures + self.errors, baseline)
        return res

    def finish(self, baseline:OrderedDict):
        self.cleanup()
        self.outputResultsFiles(baseline)

        if self.checkContainerFailure():
            print("One or more containers crashed, so testing did not complete successfully. We wrote out the results we have")
            return False
        else:
            return True

        

    def cleanup(self):
        self.lock.acquire()
        try:
            print("Removing all attack data that was downloaded during this test at: [%s]"%(self.attack_data_root_folder))
            shutil.rmtree(self.attack_data_root_folder)
            print("Successfully removed all attack data")
        finally:
            self.lock.release()
    def summarize(self)->bool:
        
        if self.checkContainerFailure() == True:
            print("Error running containers... shutting down", file=sys.stderr)
            return False
        
        
        self.lock.acquire()
        
        try:
        
            current_time = timeit.default_timer()
            
            

            if self.testing_queue.qsize() == self.total_number_of_tests:
                #Testing has not started yet. We are setting up containers
                print("***********PROGRESS UPDATE***********\n"\
                      "\tWaiting for container setup: %s\n"%(datetime.timedelta(seconds=current_time - self.start_time)))
            else:
                
                if self.container_ready_time is None:
                    #This is the first status update since container setup has completed.  Get the current time.
                    #This makes our remaining time estimates better since that estimate should not involve
                    #the container setup time  
                    self.container_ready_time = current_time

                numberOfCompletedTests = len(self.successes) + len(self.failures) + len(self.errors)
                remaining_tests = self.testing_queue.qsize()         
                testsCurrentlyRunning = self.total_number_of_tests - remaining_tests - numberOfCompletedTests
                total_execution_time_seconds = current_time - self.start_time

                test_execution_time_seconds = current_time - self.container_ready_time
                
                
                if numberOfCompletedTests == 0 or test_execution_time_seconds == 0:
                    estimated_seconds_to_finish_all_tests = "UNKNOWN"
                    estimated_completion_time_seconds = "UNKNOWN"
                else:
                    average_time_per_test = test_execution_time_seconds / numberOfCompletedTests
                    #divide testsCurrentlyRunning by 2.0 because, on average, each running test will be 50% completed
                    estimated_seconds_to_finish_all_tests = average_time_per_test * (remaining_tests + testsCurrentlyRunning/2.0)
                    estimated_completion_time_seconds = datetime.timedelta(seconds=estimated_seconds_to_finish_all_tests)
                    
                

            
                print("***********PROGRESS UPDATE***********\n"\
                "\tElapsed Time               : %s\n"\
                "\tEstimated Remaining Time   : %s\n"\
                "\tTests to run               : %d\n"\
                "\tTests currently running    : %d\n"\
                "\tTests completed            : %d\n"\
                "\t\tSuccess : %d\n"\
                "\t\tFailure : %d\n"\
                "\t\tError   : %d"%(datetime.timedelta(seconds=total_execution_time_seconds), 
                                    estimated_completion_time_seconds, 
                                    remaining_tests, 
                                    testsCurrentlyRunning,
                                    numberOfCompletedTests, 
                                    len(self.successes), 
                                    len(self.failures), 
                                    len(self.errors)))
    
        except Exception as e:
            print("Error in printing execution summary: [%s]"%(str(e)))
        finally:
            self.lock.release()
            
        
        #Return true while there are tests remaining
        completed_tests = len(self.successes) + len(self.failures) + len(self.errors)
        remaining_tests = self.total_number_of_tests - completed_tests
        return remaining_tests > 0
                
        
        
    def addResult(self, result:dict)->None:
        try:
            if result['detection_result']['success'] is False:
                #This is actually a failure of the detection, not an error. Naming is confusiong
                self.addFailure(result['detection_result'])
            elif result['detection_result']['success'] is True:
                self.addSuccess(result['detection_result'])
        except Exception as e:
            #Neither a success or a failure, so add the object to the failures queue
            print('"There was an error adding the result: [%s]'%(str(e)))
            self.addError({'detection_file':"Unknown File", "detection_error":str(result)})

