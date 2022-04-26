import csv
import glob
import logging
import os
import pathlib
import subprocess
import sys
from typing import Union
from docker import types
import datetime
import git
import yaml
from git.objects import base
from modules import testing_service
import pathlib

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

SECURITY_CONTENT_URL = "https://github.com/splunk/security_content"


DETECTION_ROOT_PATH      = "security_content/detections"
TEST_ROOT_PATH           = "security_content/tests"
DETECTION_FILE_EXTENSION = ".yml"
TEST_FILE_EXTENSION      = ".test.yml"
SSA_PREFIX = "ssa___"
class GithubService:


    def __init__(self, security_content_branch: str, commit_hash: Union[str,None], PR_number: Union[int,None] = None, persist_security_content: bool = False):

        self.security_content_branch = security_content_branch
        if persist_security_content:
            print("Getting handle on existing security_content repo!")
            self.security_content_repo_obj = git.Repo("security_content")
        else:
            print("Checking out security_content repo!")            
            self.security_content_repo_obj = self.clone_project(
                SECURITY_CONTENT_URL, f"security_content", f"develop")

        #Ensure that the branch name is valid   
        #Get all the branch names, prefixed with "origin/"
        branch_names = [branch.name for branch in self.security_content_repo_obj.remote().refs]

        if "origin/%s"%(security_content_branch) not in branch_names:
            raise(Exception("Branch name [%s] not found in valid branches.  Try running \n"\
                           "'git branch -a' to examine [%d] branches"%(security_content_branch, len(branch_names))))


        if commit_hash is not None and PR_number is not None: 
            print(f"\n************\nWARNING - both the PR_number {PR_number} and the commit_hash {commit_hash} were provided. "
                  f"You should only pass neither or one of these.  We will ASSUME you want to use the PR_number, not the commit_hash. " 
                  f"Removing the commit_hash...\n************\n")
            commit_hash = None
            
            

        if PR_number:
            ret = subprocess.run(["git", "-C", "security_content/", "fetch", "origin",
                            "refs/pull/%d/head:%s" % (PR_number, security_content_branch)], capture_output=True)
            #ret = subprocess.call(["git", "-C", "security_content/", "fetch", "origin",
            #                "refs/pull/%d/head:%s" % (PR_number, security_content_branch)])
            
            
            if ret.returncode != 0:
                raise(Exception("Error checking out repository: [%s]"%(ret.stdout.decode("utf-8") + "\n" + ret.stderr.decode("utf-8"))))
            

        # No checking to see if the hash is to a commit inside of the branch - the user
        # has to do that by hand.
        if commit_hash is not None:
            print("Checking out commit hash: [%s]" % (commit_hash))
            self.security_content_repo_obj.git.checkout(commit_hash)
        else:
            #Even if we have fetched a PR, we still MUST check out the branch to
            # be able to do anything with it. Otherwise we won't have the files
            print("Checking out branch: [%s]..." %
                  (security_content_branch), end='')
            sys.stdout.flush()
            self.security_content_repo_obj.git.checkout(
                security_content_branch)
            commit_hash = self.security_content_repo_obj.head.object.hexsha
            print("commit_hash %s" % (commit_hash))

        self.commit_hash = commit_hash

        


    def update_and_commit_passed_tests(self, results:list[dict])->bool:
        
        changed_file_paths = []
        for result in results:
            detection_obj_path = os.path.join("security_content","detections",result['detection_file'])
            
            test_obj_path = detection_obj_path.replace("detections", "tests", 1)
            test_obj_path = test_obj_path.replace(".yml",".test.yml")

            detection_obj = testing_service.load_file(detection_obj_path)
            test_obj = testing_service.load_file(test_obj_path)
            detection_obj['tags']['automated_detection_testing'] = 'passed'
            #detection_obj['tags']['automated_detection_testing_date'] = datetime.datetime.today().strftime('%Y-%m-%d-%H:%M:%S')
            
            for o in test_obj['tests']:
                if 'attack_data' in o:
                    datasets = []
                    for dataset in o['attack_data']:
                        datasets.append(dataset['data'])
                    detection_obj['tags']['dataset'] = datasets
            with open(detection_obj_path, "w") as f:
                yaml.dump(detection_obj, f, sort_keys=False, allow_unicode=True)
            
            changed_file_paths.append(detection_obj_path)
        
        relpaths = [pathlib.Path(*pathlib.Path(p).parts[1:]).as_posix() for p in changed_file_paths]
        newpath = relpaths[0]+'.wow'
        relpaths.append(newpath)
        with open('security_content/' + newpath,'w') as d:
                d.write("fake file")
        print("status results:")
        print(self.security_content_repo_obj.index.diff(self.security_content_repo_obj.head.commit))
        
        if len(relpaths) > 0:
            print('there is at least one changed file')
            print(relpaths)            
            self.security_content_repo_obj.index.add(relpaths)
            print("status results after add:")
            print(self.security_content_repo_obj.index.diff(self.security_content_repo_obj.head.commit))

            commit_message = "The following detections passed detection testing.  Their YAMLs have been updated and their datasets linked:\n - %s"%("\n - ".join(relpaths))
            self.security_content_repo_obj.index.commit(commit_message)
            return True
        else:
            return False
                
        

        
        return True

    def clone_project(self, url, project, branch):
        LOGGER.info(f"Clone Security Content Project")
        repo_obj = git.Repo.clone_from(url, project, branch=branch)
        return repo_obj


    def prune_detections(self,
                         detection_files: list[str],
                         types_to_test: list[str],
                         exclude_ssa: bool = True) -> list[str]:
    
        
    
        pruned_tests = []
    
        for detection in detection_files:
            
            if os.path.basename(detection).startswith(SSA_PREFIX) and exclude_ssa:
                continue
            with open(detection, "r") as d:
                description = yaml.safe_load(d)

                test_filepath = os.path.splitext(detection)[0].replace(
                    'detections', 'tests') + '.test.yml'
                test_filepath_without_security_content = str(
                    pathlib.Path(*pathlib.Path(test_filepath).parts[1:]))
                # If no   types are provided, then we will get everything
                if 'type' in description and (description['type'] in types_to_test or len(types_to_test) == 0):

                    if not os.path.exists(test_filepath):
                        print("Detection [%s] references [%s], but it does not exist" % (
                            detection, test_filepath))
                        #raise(Exception("Detection [%s] references [%s], but it does not exist"%(detection, test_filepath)))
                    else:
                        # remove leading security_content/ from path
                        pruned_tests.append(test_filepath_without_security_content)
                        
                else:
                    # Don't do anything with these files
                    pass
        
        if not self.ensure_paired_detection_and_test_files([], [os.path.join("security_content", p) for p in pruned_tests], exclude_ssa):
            raise(Exception("Missing one or more test/detection files. Please see the output above."))
        
        return pruned_tests

    def ensure_paired_detection_and_test_files(self, detection_files: list[str], test_files: list[str], exclude_ssa: bool = True)->bool: 
        '''
        The security_content repo contains two folders: detections and test.
        For EVERY detection in the detections folder, there must be a test.
        for EVERY test in the tests folder, there MUST be a detection.
        
        If this requirement is not met, then throw an error
        '''

        MISSING_TEMPLATE = "Missing {type} file:"\
                           "\n\tEXISTS  - {exists}"\
                           "\n\tMISSING - {missing}"\
                           

        no_missing_files = True
        #Check that all detection files have a test file
        for detection_file in detection_files:
            test_file = self.convert_detection_filename_into_test_filename(detection_file)
            if not os.path.exists(test_file):
                if os.path.basename(detection_file).startswith(SSA_PREFIX) and exclude_ssa is True:
                    print(MISSING_TEMPLATE.format(type="test", exists=detection_file, missing=test_file))
                    print("\tSince exclude_ssa is TRUE, this is not an error, just a warning")
                else:
                    print(MISSING_TEMPLATE.format(type="test", exists=detection_file, missing=test_file))
                    no_missing_files = False
                    
        #Check that all test files have a detection file
        for test_file in test_files:
            detection_file = self.convert_test_filename_into_detection_filename(test_file)
            if not os.path.exists(detection_file):
                if os.path.basename(test_file).startswith(SSA_PREFIX) and exclude_ssa is True:
                    print(MISSING_TEMPLATE.format(type="detection", exists=test_file, missing=detection_file))
                    print("\tSince exclude_ssa is TRUE, this is not an error, just a warning")
                else:
                    print(MISSING_TEMPLATE.format(type="detection", exists=test_file, missing=detection_file))
                    no_missing_files = False
        
                    
        return no_missing_files
    
    def convert_detection_filename_into_test_filename(self, detection_filename:str) ->str:
        head, tail = os.path.split(detection_filename)
        
        assert head.startswith(DETECTION_ROOT_PATH), \
               f"Error - Expected detection filename to start with [{DETECTION_ROOT_PATH}] but instead got {detection_filename}"
                
        updated_head = head.replace(DETECTION_ROOT_PATH, TEST_ROOT_PATH, 1)

        
        assert tail.endswith(DETECTION_FILE_EXTENSION),\
               f"Error - Expected detection filename to end with [{DETECTION_FILE_EXTENSION}] but instead got [{detection_filename}]"
        updated_tail = TEST_FILE_EXTENSION.join(tail.rsplit(DETECTION_FILE_EXTENSION))

        return os.path.join(updated_head, updated_tail)

    def convert_test_filename_into_detection_filename(self, test_filename:str) ->str :
        head, tail = os.path.split(test_filename)
        

        assert head.startswith(TEST_ROOT_PATH), \
               f"Error - Expected test filename to start with [{TEST_ROOT_PATH}] but instead got {test_filename}"

        updated_head = head.replace(TEST_ROOT_PATH, DETECTION_ROOT_PATH, 1)

        
        assert tail.endswith(TEST_FILE_EXTENSION), \
               f"Error - Expected test filename to end with [{TEST_FILE_EXTENSION}] but instead got [{test_filename}]"
        updated_tail = DETECTION_FILE_EXTENSION.join(tail.rsplit(TEST_FILE_EXTENSION))

        return os.path.join(updated_head, updated_tail)


    def get_test_files(self, mode: str, folders: list[str],   types: list[str],
                       detections_list: Union[list[str], None]) -> list[str]:

        #Every test should have a detection associated with it.  It is NOT necessarily
        #true that all detections should have a test associated with them.  For example,
        #only certain types of detections should have a test associated with them.
        self.verify_all_tests_have_detections(folders, types)
        
        if mode == "changes":
            tests = self.get_changed_test_files(folders, types)
        elif mode == "selected":
            if detections_list is None:
                # It's actually valid to supply an EMPTY list of files and the test should pass.
                # This can occur when we try to test, for example, 1 detection but start 2 containers.
                # We still want this to pass testing, so we shouldn't fail there!
                print("Trying to test a list of files, but None were provided", file=sys.stderr)
                sys.exit(1)

            elif detections_list is not None:
                tests = self.get_selected_test_files(detections_list, types)
            else:
                # impossible to get here
                print(
                    "Impossible to get here.  Just kept to make the if/elif more self describing", file=sys.stderr)
                sys.exit(1)

        elif mode == "all":
            tests = self.get_all_tests_and_detections(folders,  types)
        else:
            print(
                "Error, unsupported mode [%s].  Mode must be one of %s", file=sys.stderr)
            sys.exit(1)


        return tests

    def get_selected_test_files(self,
                                detection_file_list: list[str],
                                types_to_test: list[str] = [
                                    "Anomaly", "Hunting", "TTP"]) -> list[str]:

        return self.prune_detections(detection_file_list, types_to_test)

    def verify_all_tests_have_detections(self, folders: list[str] = [
                                         'endpoint', 'cloud', 'network'],
                                     types_to_test: list[str] = [
                                         "Anomaly", "Hunting", "TTP"],
                                         exclude_ssa:bool=True)->bool:
        all_tests = []
        for folder in folders:
            #Get all the tests in a folder 
            tests = self.get_all_files_in_folder(os.path.join(TEST_ROOT_PATH, folder), "*")
            #Convert all of those tests to detection paths
            for test in tests:
                all_tests.append(test)


        if not self.ensure_paired_detection_and_test_files([], all_tests, exclude_ssa):
            raise(Exception("Missing one or more detection files. Please see the output above."))
        
        return True


    def get_all_tests_and_detections(self,
                                     folders: list[str] = [
                                         'endpoint', 'cloud', 'network'],
                                     types_to_test: list[str] = [
                                         "Anomaly", "Hunting", "TTP"]) -> list[str]:
        detections = []
        for folder in folders:
            detections.extend(self.get_all_files_in_folder(os.path.join(DETECTION_ROOT_PATH, folder), "*"))

        # Prune this down to only the subset of detections we can test
        return self.prune_detections(detections, types_to_test)
        
    def get_all_files_in_folder(self, foldername: str, extension: str) -> list[str]:
        filenames = glob.glob(os.path.join(foldername, extension))
        return filenames

    def get_changed_test_files(self, folders=['endpoint', 'cloud', 'network'],   types_to_test=["Anomaly", "Hunting", "TTP"]) -> list[str]:

        branch1 = self.security_content_branch
        branch2 = 'develop'
        g = git.Git('security_content')
        all_changed_test_files = []

        all_changed_detection_files = []
        if branch1 != 'develop':
            if self.commit_hash is None:
                differ = g.diff('--name-status', branch2 + '...' + branch1)
            else:
                differ = g.diff('--name-status', branch2 +
                                '...' + self.commit_hash)

            changed_files = differ.splitlines()

            for file_path in changed_files:
                # added or changed test files
                if file_path.startswith('A') or file_path.startswith('M'):
                    if 'tests' in file_path and os.path.basename(file_path).endswith('.test.yml'):
                        all_changed_test_files.append(file_path)

                    # changed detections
                    if 'detections' in file_path and os.path.basename(file_path).endswith('.yml'):
                        all_changed_detection_files.append(file_path)
        else:
            print("Looking for changed detections by diffing [%s] against [%s].  They are the same branch, so none were returned." % (
                branch1, branch2), file=sys.stderr)
            return []

        
        # all files have the format A\tFILENAME or M\tFILENAME.  Get rid of those leading characters
        all_changed_test_files = [os.path.join("security_content", name.split(
            '\t')[1]) for name in all_changed_test_files if len(name.split('\t')) == 2]

        all_changed_detection_files = [os.path.join("security_content", name.split(
            '\t')[1]) for name in all_changed_detection_files if len(name.split('\t')) == 2]
         

        #Trim out any of the tests/detection  that are not in the selected folders, but at least print a notice
        # to the user.
        changed_test_files = [x for x in all_changed_test_files if len(pathlib.Path(x).parts) > 3 and 
                             pathlib.Path(x).parts[2] in folders ]
        changed_detection_files = [x for x in all_changed_detection_files if 
                                  (len(pathlib.Path(x).parts) > 3 and pathlib.Path(x).parts[2] in folders) ]
       
        #Print out the skipped tests to the user
        for missing in set(changed_test_files).symmetric_difference(all_changed_test_files):
            print("Ignoring modified test [%s] not in set of selected folders: %s"%(missing,folders)) 
        
        for missing in set(changed_detection_files).symmetric_difference(all_changed_detection_files):
            print("Ignoring modified detecton [%s] not in set of selected folders: %s"%(missing,folders))
                
        # Convert the test files to the detection file equivalent. 
        # Note that some of these tests may be baselines and their associated 
        # detection could be in experimental or not in the experimental folder
        converted_test_files = []
        #for test_filepath in changed_test_files:
        #    detection_filename = str(pathlib.Path(
        #        *pathlib.Path(test_filepath).parts[-2:])).replace("tests", "detections", 1)
        #    converted_test_files.append(detection_filename)
        
        
        #Get the appropriate detection file paths for a modified test file
        for test_filepath in changed_test_files:
            folder_and_filename =  str(pathlib.Path(*pathlib.Path(test_filepath).parts[-2:]))
            folder_and_filename_fixed_suffix = folder_and_filename.replace(".test.yml",".yml")
            result = None
            for f in glob.glob("security_content/detections/**/" + folder_and_filename_fixed_suffix,recursive=True):
                if result != None:
                    #found a duplicate filename that matches
                    raise(Exception("Error - Found at least two detection files to match for test file [%s]: [%s] and [%s]"%(test_filepath, result, f)))
                else:
                    result = f
            if result is None:
                raise(Exception("Error - Failed to find detection file for test file [%s]"%(test_filepath)))
            else:
                converted_test_files.append(result)
        
        
        
        for name in converted_test_files:
            if name not in changed_detection_files:
                changed_detection_files.append(name)
        

        return self.prune_detections(changed_detection_files, types_to_test)

        #detections_to_test,_,_ = self.filter_test_types(changed_detection_files)
        # for f in detections_to_test:
        #    file_path_base = os.path.splitext(f)[0].replace('detections', 'tests') + '.test'
        #    file_path_new = file_path_base + '.yml'
        #    if file_path_new not in changed_test_files:
        #        changed_test_files.append(file_path_new)

        #print("Total things to test (test files and detection files changed): [%d]"%(len(changed_test_files)))
        # for l in changed_test_files:
        #    print(l)
        # print(len(changed_test_files))
        #import time
        # time.sleep(5)

    def filter_test_types(self, test_files, test_types=["Anomaly", "Hunting", "TTP"]):
        files_to_test = []
        files_not_to_test = []
        error_files = []
        for filename in test_files:
            try:
                with open(os.path.join("security_content", filename), "r") as fileData:
                    yaml_dict = list(yaml.safe_load_all(fileData))[0]
                    if 'type' not in yaml_dict.keys():
                        print(
                            "Failed to find 'type' in the yaml for: [%s]" % (filename))
                        error_files.append(filename)
                    if yaml_dict['type'] in test_types:
                        files_to_test.append(filename)
                    else:
                        files_not_to_test.append(filename)
            except Exception as e:
                print("Error on trying to scan [%s]: [%s]" % (
                    filename, str(e)))
                error_files.append(filename)
        print("***Detection Information***\n"
              "\tTotal Files       : %d"
              "\tFiles to test     : %d"
              "\tFiles not to test : %d"
              "\tError files       : %d" % (len(test_files), len(files_to_test), len(files_not_to_test), len(error_files)))
        import time
        time.sleep(5)
        return files_to_test, files_not_to_test, error_files
