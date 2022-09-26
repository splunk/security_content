from typing import Union
import pathlib
import yaml
import os
import json
import timeit
from datetime import timedelta

def load_file(file_path):
    try:

        with open(file_path, 'r', encoding="utf-8") as stream:
            try:
                file = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                raise(Exception("ERROR: parsing YAML for {0}:[{1}]".format(file_path, str(exc))))
    except Exception as e:
        raise(Exception("ERROR: opening {0}:[{1}]".format(file_path, str(e))))
    return file






class TestResult:
    def __init__(self, generated_exception:Union[dict,None] = None, no_exception:Union[dict,None]=None):

        
        #always include all of these fields, even if there is an         
        self.runDuration = None
        self.scanCount = None
        self.eventCount = None
        self.resultCount = None
        self.performance = None
        self.search = None
        self.message = None
        self.exception = False
        self.success = False

        if generated_exception is not None:
            self.message = generated_exception['message']
            self.logic = False
            self.noise = False
            self.exception = True
        elif no_exception is not None:
            self.exception = False            
            self.noise = False

            
            if int(no_exception['resultCount']) == 1:
                self.logic = True
                self.message = "Test execution successful"

            else:
                self.logic = False
                self.message = "Test execution failed - search did not return any results"
            
            #populate all the fields we want to populate for a test that ran to completion
            self.runDuration = float(no_exception['runDuration'])
            self.scanCount = int(no_exception['scanCount'])
            self.eventCount = int(no_exception['eventCount'])
            self.resultCount = int(no_exception['resultCount'])
            self.performance = no_exception['performance']
            self.search = no_exception['search']

            #This may change in the future as we include different types of tests like noise
            self.success = self.logic

            #print("Raw Job Dict Content")
            #for k,v in no_exception.items():
            #    print(f"{str(k)}: {str(v)}")

        else:
            raise(Exception("Result created with indeterminate success"))

class DetectionResult:
    def __init__(self, testResults:list[TestResult]) -> None:
        #summarize all the results
        self.runDuration = sum([t.runDuration for t in testResults if t.runDuration is not None])
        #Get the result for the detection by combining the results of all the individual tests
        self.success = not(False in [t.success for t in testResults if t.success is not None])
        self.logic = not(False in [t.logic for t in testResults if t.logic is not None])
        self.noise = not(False in [t.noise for t in testResults if t.noise is not None])

class Detection:
    def __init__(self, detection_file:pathlib.Path):
        if detection_file == None:
            print("Detection file path was None!")
            import sys
            sys.exit(1)
        self.detectionFile = DetectionFile(detection_file)

        #Infer the test file name from the detection file name
        self.testFile = TestFile(detectionFile = self.detectionFile)


        self.result:Union[None, DetectionResult] = None    

    def get_detection_result(self):
        if len(self.testFile.tests) == 0:
            raise(Exception(f"Detection {self.detectionFile.path} had no tests associated with it"))
        else:
            testResults = [test.result for test in self.testFile.tests if test.result is not None]
            self.result = DetectionResult(testResults)
    
    

class DetectionFile:
    def __init__(self, detection_file_path:pathlib.Path):
        if not detection_file_path.exists():
            raise(Exception(f"The following Detection file does not exist: {detection_file_path}"))
        self.path = detection_file_path
        try:
            detection_file = load_file(detection_file_path)
        except Exception as e:
            raise(Exception(f"Error loading the detection file: {str(e)}"))
        
        try:
            self.name = detection_file.get("name")
            self.id = detection_file.get("id")
            self.type = detection_file.get("type")
            self.search = detection_file.get("search")
            
        except Exception as e:
            raise(Exception(f"Failed to find a required key in the detection file {self.path}: {str(e)}"))



class TestFile:
    def __init__(self, detectionFile:DetectionFile, test_file:Union[None, pathlib.Path] = None):
        self.detectionFile = detectionFile
        if test_file is not None:
            #Override deriving the test file path from the detection file
            #we already have the test file, so use that path
            pass
        else:
            #Infer the test file path
            
            detection_file_path_parts = list(detectionFile.path.parts)
            detections_folder_index = (len(detection_file_path_parts)-1) - detection_file_path_parts[::-1].index("detections")
            
            detection_file_path_parts[detections_folder_index] = "tests"
            detection_file_path_parts[-1] = detection_file_path_parts[-1].replace(".yml", ".test.yml")
            test_file = pathlib.Path(os.path.join(*detection_file_path_parts))


        
        if not test_file.exists():
            raise(Exception(f"The following test file does not exist: {test_file}"))
        
        self.path = test_file

        test_data = load_file(test_file)
        #Set the attributes
        self.name = test_data['name']
        self.tests = self.get_tests(test_data['tests'])
    def get_tests(self, test_data:list[dict]):
        return [Test(t,self.detectionFile) for t in test_data]


class Test:
    def __init__(self, test:dict, detectionFile:DetectionFile):
        self.detectionFile = detectionFile
        self.name = test['name']
        self.file = test['file']
        self.pass_condition = test['pass_condition']
        self.earliest_time = test['earliest_time']
        self.latest_time = test['latest_time']
        self.attack_data = self.get_attack_data(test['attack_data'])
        self.baselines = self.getBaselines(test.get("baselines",[]))
        self.result:Union[None, TestResult] = None
    def get_attack_data(self, attack_datas: list[dict]):
        return [AttackData(d) for d in attack_datas]
    
    def getBaselines(self, baselines: list[dict]):
        app_root = self.detectionFile.path.resolve().parent.parent.parent
        return [Baseline(b,app_root) for b in baselines]
    
    def error_in_baselines(self)->bool:
        for b in self.baselines:
            if b.result is not None and b.result.exception is True:
                print(f"Error executing baseline: {b.result.message}")
                return True
        return False
    def all_baselines_successful(self)->bool:
        for b in self.baselines:
            if b.result is None or b.result.success is False:
                print(f"Baseline {b.name} was not successful")
                return False
        return True
    

class Baseline:
    def __init__(self, baseline:dict, app_root:pathlib.Path):
        self.name = baseline['name']
        self.file = baseline['file']
        self.pass_condition = baseline['pass_condition']
        self.earliest_time = baseline['earliest_time']
        self.latest_time = baseline['latest_time']
        self.baseline = DetectionFile(pathlib.Path(os.path.join(app_root,self.file)))
        self.result:Union[None,TestResult] = None
        

class AttackData:
    def __init__(self, attack_data:dict, rewrite_path:Union[None,pathlib.Path]=None):
        self.file_name = attack_data['file_name']
        self.data = attack_data['data']
        self.source = attack_data['source']
        self.sourcetype = attack_data['sourcetype']
        self.index = attack_data.get('custom_index', 'main')
        self.update_timestamp = attack_data.get("update_timestamp", False)

        if rewrite_path is not None:
            #check that the data file exists
            URL_BASE_MEDIA = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
            URL_BASE_RAW = "https://raw.githubusercontent.com/splunk/attack_data/master/"
            if URL_BASE_RAW in attack_data['data']:
                new_path = pathlib.Path(os.path.join(rewrite_path, attack_data['data'].replace(URL_BASE_RAW, '')))
            elif URL_BASE_MEDIA in attack_data['data']:
                new_path = pathlib.Path(os.path.join(rewrite_path, attack_data['data'].replace(URL_BASE_MEDIA, '')))
            
            else:
                #print(URL_BASE_MEDIA)
                #print(URL_BASE_RAW)
                print(f"Bad URL for: {attack_data['data']}")
                return
                
            
            if new_path.exists():
                self.data = str(new_path)
            else:
                raise(Exception(f"Error rewriting data path to local:\n\t{attack_data['data']}--->{new_path}"))
            
        
            
       

class ResultsManager:
    def __init__(self):
        self.detections:list[Detection] = []
        

        self.startTime = timeit.default_timer()
        self.endTime:Union[None, float] = None


        # These are important for a running tally. Final summarization and 
        # output will independently calcualte these, though
        self.result_count = 0
        self.pass_count = 0
        self.fail_count = 0


    def addCompletedDetection(self, detection:Detection):
        #Record the overall result of the detection
        
        self.result_count += 1
        
        if detection.result is None:
            self.fail_count += 1 
            raise(Exception(f"Found a detection result to be 'None' for detection: {detection.detectionFile.path}"))
        
        if detection.result is not None and detection.result.success == True:
            self.pass_count += 1
        else:
            self.fail_count += 1 
        
        
        #We keep the whole thing because it removes the need to duplicate
        #certain fields when generating the summary
        self.detections.append(detection)
    


    def generate_results_file(self, filePath:pathlib.Path, root_folder:pathlib.Path = pathlib.Path("test_results"))->bool:
        #Make the folder if it doesn't already exist.  If it does, that's ok
        root_folder.mkdir(parents=True, exist_ok=True)
        full_path = root_folder / filePath
        try:
            background = self.generate_background_section()
            summary = self.generate_summary_section()
            detections = self.generate_detections_section()
            obj = {"background": background, "summary": summary, "detections": detections}
            with open(full_path, "w") as output:
                json.dump(obj, output, indent=3)
            return True
        except Exception as e:
            print(f"Error generating result file: {str(e)}")
            return False
    
    def generate_summary_section(self)->dict:
        if self.endTime is None:
            self.endTime = timeit.default_timer()
        
        background = {}
        background['detections'] = len(self.detections)
        background['detections_pass'] = len([d for d in self.detections if d.result is not None and d.result.success == True])
        background['detections_fail'] = len([d for d in self.detections if d.result is not None and d.result.success == False])
        
        background['tests'] = sum([len(d.testFile.tests) for d in self.detections])
        all_tests:list[Test] = []
        for detection in self.detections:
            for test in detection.testFile.tests:
                all_tests.append(test)
        background['tests_pass'] = len([t for t in all_tests if t.result is not None and t.result.success == True])
        background['tests_fail'] = len([t for t in all_tests if t.result is not None and t.result.success == False])
        background['total_time'] = str(timedelta(seconds = round(self.endTime - self.startTime)))

        


        return background

    def generate_detections_section(self)->list[dict]:
        results = []
        for detection in self.detections:
            success = True
            thisDetection = {"name"  : detection.detectionFile.name,
                             "id"    : detection.detectionFile.id,
                             "search": detection.detectionFile.search,
                             "path"  : str(detection.detectionFile.path),
                             "tests" : []}
            for test in detection.testFile.tests:
                if test.result is None:
                    raise(Exception(f"Detection {detection.detectionFile.name}, Test {test.name} in file {detection.testFile.path} was None, but should not be!"))
                testResult = {
                    "name": test.name,
                    "attack_data": [d.data for d in test.attack_data],
                    "success": test.result.success,
                    "logic": test.result.logic,
                    "noise": test.result.noise,
                    #"performance": test.result.performance,
                    "resultCount": test.result.resultCount,
                    "runDuration": test.result.runDuration,
                }
                thisDetection['tests'].append(testResult)
                success = success and test.result.success
            thisDetection['success'] = success
            results.append(thisDetection)

        return results
    
    def generate_background_section(self)->dict:
        return {}

