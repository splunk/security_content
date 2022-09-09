from typing import Union
import pathlib
import yaml
import os


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

class Result:
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
            if no_exception['eventCount'] == 1:
                self.logic = True
                self.message = "Test execution successful"

            else:
                self.logic = False
                self.message = "Test execution failed - search did not return any results"
            
            #populate all the fields we want to populate for a test that ran to completion
            self.runDuration = no_exception['runDuration']
            self.scanCount = no_exception['scanCount']
            self.eventCount = no_exception['eventCount']
            self.resultCount = no_exception['resultCount']
            self.performance = no_exception['performance']
            self.search = no_exception['search']

            #This may change in the future as we include different types of tests like noise
            self.success = self.logic
        
        else:
            raise(Exception("Result created with indeterminate success"))

        
class Detection:
    def __init__(self, detection_file:pathlib.Path):
        self.detectionFile = DetectionFile(detection_file)

        #Infer the test file name from the detection file name
        self.testFile = TestFile(detectionFile = self.detectionFile)


        self.result:Union[None, Result] = None    
    
    

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
        self.attack_data = test['attack_data']
        self.baselines = self.getBaselines(test.get("baselines",[]))

        self.result:Union[None, Result] = None
    def get_attack_data(self, attack_datas: list[dict]):
        return [AttackData(d) for d in attack_datas]
    
    def getBaselines(self, baselines: list[dict]):
        return [Baseline(b) for b in baselines]
    

class Baseline:
    def __init__(self, baseline:dict):
        self.name = baseline['name']
        self.file = baseline['file']
        self.pass_condition = baseline['pass_condition']
        self.earliest_time = baseline['earliest_time']
        self.latest_time = baseline['latest_time']
        print("Warning loading baseline - we are resolving to a static path and must fix this")
        self.baseline = DetectionFile(pathlib.Path(os.path.join("security_content",self.file)))
        self.result:Union[None,Result] = None
        

class AttackData:
    def __init__(self, attack_data:dict):
        self.file_name = attack_data['file_name']
        self.data = attack_data['data']
        self.source = attack_data['source']
        self.sourcetype = attack_data['sourcetype']
        self.index = attack_data.get('custom_index', 'main')
