from cgi import test
import csv
from curses import pair_number
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
import shutil
import re
# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

SECURITY_CONTENT_URL = "https://github.com/splunk/security_content"
LOCAL_PR_BRANCH = "LOCAL_PR_%d_TESTING_BRANCH"
SECURITY_CONTENT_MAIN_BRANCH = "develop"
SECURITY_CONTENT_DIRECTORY_NAME = "security_content/"



class GithubService:


    def __init__(self, security_content_branch: Union[str,None], commit_hash: Union[str,None], PR_number: Union[int,None], persist_security_content:bool = False):
        
        if PR_number is not None and security_content_branch is not None:
            print(f"Warning - branch {security_content_branch} and PR_number {PR_number} were provided.  You may only provide branch OR PR_number, not both. Dropping branch and assuming PR number...")
            security_content_branch = None
        if PR_number is None and security_content_branch is None and commit_hash is None:
            raise(Exception("PR number, branch, and commit hash were all none.  There is nothing we can check out."))


        if PR_number is not None :
            if commit_hash is not None:
                print(f"PR number {PR_number} and commit hash {commit_hash} provided.  We will ignore the commit hash and check out latest most updated version of the PR.")
                commit_hash = None
            if security_content_branch is not None:
                print(f"PR number {PR_number} and branch {security_content_branch} provided.  We will ignore the branch and check out latest most updated version of the PR.")
                commit_hash = None
        
                

        self.PR_number = PR_number
        
        if persist_security_content is False and os.path.exists(SECURITY_CONTENT_DIRECTORY_NAME):
            print("Deleting the security_content directory...",end='')
            sys.stdout.flush()
            try:
                shutil.rmtree("security_content/", ignore_errors=True)
            except Exception as e:
                print(
                    "Error - could not remove the security_content directory: [%s].\n\tQuitting..." % (str(e)))
                sys.exit(1)
            print("done")
        
        if persist_security_content is True and os.path.exists(SECURITY_CONTENT_DIRECTORY_NAME):
            print("\n********************************************************************************\n\n"
                  f"Warning: the {SECURITY_CONTENT_DIRECTORY_NAME} directory exists and you have set\n"
                  "persist_security_content to true.  We will intentionally not overwrite/update/check\n"
                  "out the repo - doing so can clobber local changes.  Only use this option if you are\n"
                  "using a very low bandwidth connection or have made local changes you wish to test\n"
                  "without pushing them to the repo.\n\n"
                  "********************************************************************************\n")

        #Now get the security_content repo if it doesn't exist:
        #It didn't exist in the first place
        #It was removed bycause persist_security_content was false
        if not os.path.exists(SECURITY_CONTENT_DIRECTORY_NAME):
            print(f"Checking out the repo [{SECURITY_CONTENT_URL}]...",end='')
            sys.stdout.flush()
            self.security_content_repo_obj = self.clone_project(SECURITY_CONTENT_URL, SECURITY_CONTENT_DIRECTORY_NAME, SECURITY_CONTENT_MAIN_BRANCH)
            print("done")
        else:
            self.security_content_repo_obj = git.Repo("security_content")


        #For a Fork PR, that branch may not exist in security_content.  Or, worse, it may
        #exist but have different content. Make sure to account for this.
        if self.PR_number is not None:
            self.security_content_remote_branch = security_content_branch
            self.security_content_local_branch = LOCAL_PR_BRANCH%self.PR_number

            print(f"Checking out pull request {PR_number}...",end='')
            sys.stdout.flush()
            
            self.security_content_repo_obj.git.fetch("origin", f"pull/{self.PR_number}/head:{self.security_content_local_branch}")
            
            self.security_content_repo_obj.git.checkout(self.security_content_local_branch)
            print("done")
            
        elif commit_hash is not None:
                if security_content_branch is None:
                    security_content_branch = f"UNKNOWN_BRANCH_{commit_hash}"
                self.security_content_remote_branch = security_content_branch
                self.security_content_local_branch =  security_content_branch

                print(f"Checking out by commit hash {commit_hash}...",end='')
                self.security_content_repo_obj.git.checkout(commit_hash)
                sys.stdout.flush()
                print("done")
                #Not checking to see that the hash is in the branch it claims to be in. This is tricky because the
                #commit could be in several branches...

                #Ensure that the commit hash we just checked out is in the branch we think it is
                #output = self.security_content_repo_obj.git.branch("-a", "--contains", commit_hash)
                #matches = re.search(f"\*.*{self.security_content_local_branch}" ,str(output))
                #if matches == 1:
                #    raise(Exception(f"The commit hash {commit_hash} was found, but not found in the "
                #                     "specified branch {self.security_content_local_branch}"))
        
        elif security_content_branch is not None:
            self.security_content_remote_branch = security_content_branch
            self.security_content_local_branch  = security_content_branch
            branch_names = [branch.name for branch in self.security_content_repo_obj.remote().refs]
            #Ensure that the branch name is valid (it is a real branch in our repo)
            if "origin/%s"%(self.security_content_remote_branch) not in branch_names:
                raise(Exception("Branch name [%s] not found in valid branches.  Try running \n"\
                           "'git branch -a' to examine [%d] branches"%(self.security_content_remote_branch, len(branch_names))))
            
            print(f"Checking out branch: [{security_content_branch}]...", end='')
            sys.stdout.flush()
            
            try:
                self.security_content_repo_obj.git.checkout(security_content_branch)
                print("done")
            except Exception as e:
                print(f"\nError checking out branch [{security_content_branch}]:\n{str(e)}", file=sys.stderr)
                response = input(f"THIS WILL OVERWRITE LOCAL CHANGES TO BRANCH [{security_content_branch}]\n\t @ {os.path.abspath(SECURITY_CONTENT_DIRECTORY_NAME)}\n\tType 'yes' if you want to proceed: ")
                if response == 'yes':
                    try:
                        self.security_content_repo_obj.git.checkout(security_content_branch, "-f")
                    except Exception as e:
                        print(f"Another error checking out the branch {security_content_branch}: {str(e)}\n\tQuitting...",file=sys.stderr)
                        sys.exit(1)
                else:
                    print(f"Your response '{response}' was not 'yes'. We did not overwirte the repo.\n\tQuitting",file=sys.stderr)
                    sys.exit(1)
                print(f"Successfully checked out {security_content_branch}. Local changes were overwritten at your request.")


             
            
            

        else:
            raise(Exception("Could not check out by PR number, commit hash, or branch"))



            #Branch should not be none here
            self.security_content_remote_branch = security_content_branch
            self.security_content_local_branch = security_content_branch
            #Ensure that the branch name is valid   
            #Get all the branch names, prefixed with "origin/"
            branch_names = [branch.name for branch in self.security_content_repo_obj.remote().refs]

            #Ensure that the branch name is valid (it is a real branch in our repo)
            if "origin/%s"%(self.security_content_remote_branch) not in branch_names:
                raise(Exception("Branch name [%s] not found in valid branches.  Try running \n"\
                           "'git branch -a' to examine [%d] branches"%(self.security_content_remote_branch, len(branch_names))))
            
                

            else:
                print(f"Checking out branch: [{security_content_branch}]...", end='')
                sys.stdout.flush()
                self.security_content_repo_obj.git.checkout(security_content_branch)
                print("done")

        if (commit_hash !=  None) and (commit_hash != self.security_content_repo_obj.head.object.hexsha):
            print("Warning: commit hash in configuration file [{commit_hash}] did NOT match the commit "
                  "hash of the PR [{self.security_content_repo_obj.head.object.hexsha}].  We just warn "
                  "about this and update the commit hash in the new test file.") 
        
        self.commit_hash = self.security_content_repo_obj.head.object.hexsha





        '''
        #If the directory exists, we do a checkout on develop and pull to make sure we have the latest content for develop
        try:
            if os.path.exists(SECURITY_CONTENT_DIRECTORY_NAME):
                print(f"SECURITY_CONTENT_DIRECTORY_NAME exists.  Getting the most updated version of the main branch ({SECURITY_CONTENT_MAIN_BRANCH})...",end='')
                sys.stdout.flush()
                
                self.security_content_repo_obj = git.Repo(SECURITY_CONTENT_DIRECTORY_NAME)
                
                #Make sure we're on the right branch (develop)
                self.security_content_repo_obj.git.checkout(SECURITY_CONTENT_MAIN_BRANCH)
                
                #Make sure that branch is up to date
                self.security_content_repo_obj.git.pull()
                
  
        
  
            else:
                #the folder did not exist, so clone the repo
                print(f"{SECURITY_CONTENT_DIRECTORY_NAME} does not exist.  Downloading it and switching to the main branch ({SECURITY_CONTENT_MAIN_BRANCH})...",end='')
                sys.stdout.flush()

                self.security_content_repo_obj = self.clone_project(SECURITY_CONTENT_URL, f"security_content", f"develop")
        except Exception as e:
            raise(Exception(f"Failure updating {SECURITY_CONTENT_DIRECTORY_NAME} folder - is it a valid repo? - [{str(e)}]"))

        print("done")
        
        if self.PR_number is not None:
            self.security_content_remote_branch = security_content_branch
            self.security_content_local_branch = LOCAL_PR_BRANCH%self.PR_number
        else:
            self.security_content_remote_branch = security_content_branch
            self.security_content_local_branch = security_content_branch


        #Ensure that the branch name is valid   
        #Get all the branch names, prefixed with "origin/"
        branch_names = [branch.name for branch in self.security_content_repo_obj.remote().refs]

        #Validate that the branch name is valid.  For a PR, this should be the branch that the PR resides in
        if "origin/%s"%(self.security_content_remote_branch) not in branch_names:
            raise(Exception("Branch name [%s] not found in valid branches.  Try running \n"\
                           "'git branch -a' to examine [%d] branches"%(self.security_content_remote_branch, len(branch_names))))


        if commit_hash is not None and PR_number is not None: 
            print(f"\n************\nWARNING - both the PR_number {PR_number} and the commit_hash {commit_hash} were provided. "
                  f"You should only pass neither or one of these.  We will ASSUME you want to use the PR_number, not the commit_hash. " 
                  f"Removing the commit_hash...\n************\n")
            commit_hash = None
            
            

        if PR_number:
            print(f"Fetching PR {self.PR_number} into local branch {self.security_content_local_branch}...",end='')
            self.security_content_repo_obj.git.fetch("origin", f"pull/{self.PR_number}/head:{self.security_content_local_branch}")
            self.security_content_repo_obj.git.checkout(self.security_content_local_branch)
            
        elif commit_hash is not None:
            # No checking to see if the hash is to a commit inside of the branch - the user
            # has to do that by hand.
            print("Checking out commit hash: [%s]..." % (commit_hash),end='')
            self.security_content_repo_obj.git.checkout(commit_hash)
            
        else:
            #Just checking out and testing a branch
            print("Checking out branch: [%s]..." %
                  (security_content_branch), end='')
            sys.stdout.flush()
            self.security_content_repo_obj.git.checkout(security_content_branch)
        #Pull to make sure we are up to date
        
        
        #Print completion and store the commit hash
        
        print(f"done")
        if (commit_hash !=  None) and (commit_hash != self.security_content_repo_obj.head.object.hexsha):
            print("Warning: commit hash in configuration file [{commit_hash}] did NOT match the commit "
                  "hash of the PR [{self.security_content_repo_obj.head.object.hexsha}].  We just warn "
                  "about this and update the commit hash in the new test file.") 
        
        commit_hash = self.security_content_repo_obj.head.object.hexsha
        self.commit_hash = commit_hash
        
        if self.PR_number is not None:
            #Verify that, if this was a PR, that the PR exists in the branch we believe it does
            output = self.security_content_repo_obj.git.branch("-a", "--contains", commit_hash)
            print(output)
            print("***")
            print(f"remotes/origin/{self.security_content_remote_branch}")
            if f"remotes/origin/{self.security_content_remote_branch}" not in output:
                #raise(Exception(f"PR number {self.PR_number} not found in branch {self.security_content_remote_branch}"))
                print(f"PR number {self.PR_number} not found in branch {self.security_content_remote_branch}")
                print("maybe this is a remote pr? or maybe you gave the wrong branch?")

        '''


        


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
                         detections_to_prune: list[str],
                         types_to_test: list[str],
                         previously_successful_tests: list[str],
                         exclude_ssa: bool = True,
                         summary_file: str = None) -> list[str]:
        pruned_tests = []
        csvlines = []
        
        for detection in detections_to_prune:
            if os.path.basename(detection).startswith("ssa") and exclude_ssa:
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
                    elif test_filepath_without_security_content in previously_successful_tests:
                        print(
                            "Ignoring test [%s] before it has already passed previously" % (detection))
                    else:
                        # remove leading security_content/ from path
                        pruned_tests.append(
                            test_filepath_without_security_content)
                        if summary_file is not None:
                            try:
                                mitre_id = str(
                                    description['tags']['mitre_attack_id'])
                            except:
                                mitre_id = 'NONE'
                            try:

                                csvlines.append({'name': description['name'], 'filename': detection, 'description': description['description'],
                                                 'search': description['search'], 'mitre_attack_id': mitre_id, 'security_domain': description['tags']['security_domain'],
                                                 'Relevant': '', 'Comments': '', "Runnable on SSA?": str(os.path.basename(detection).startswith("ssa"))})
                            except Exception as e:
                                print("Error outputting summary for [%s]: [%s]" % (
                                    detection, str(e)))
                else:
                    # Don't do anything with these files
                    pass

        if summary_file is not None:
            print("writing")
            with open(summary_file, 'w') as csvfile:
                fieldnames = ['name', 'filename', 'description', 'search', 'mitre_attack_id',
                              'security_domain', 'Runnable on SSA?', 'Relevant', 'Comments']
                writer = csv.DictWriter(
                    csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
                writer.writeheader()
                for r in csvlines:
                    writer.writerow(r)

        return pruned_tests

    def get_test_files(self, mode: str, folders: list[str],   types: list[str],
                       detections_list: Union[list[str], None],
                       detections_file=Union[str, None]) -> list[str]:
        if mode == "changes":
            tests = self.get_changed_test_files(folders, types)
        elif mode == "selected":
            if detections_list is None and detections_file is None:
                # It's actually valid to supply an EMPTY list of files and the test should pass.
                # This can occur when we try to test, for example, 1 detection but start 2 containers.
                # We still want this to pass testing, so we shouldn't fail there!
                print(
                    "Trying to test a list of files, but None were provided", file=sys.stderr)
                sys.exit(1)

            elif detections_list is not None and detections_file is not None:
                print("Both detections_list [%s] and detections_file [%s] were provided.  "
                      "Because these confilect, we cannot test.\n\tQuitting..." %
                      (detections_list, detections_file), file=sys.stderr)
                sys.exit(1)
            elif detections_list is not None:
                tests = self.get_selected_test_files(detections_list, types)
            elif detections_file is not None:
                try:
                    with open(detections_file, 'r') as f:
                        data = f.readlines()
                    # Strip all whitespace from lines and exclude lines that are just whitespace
                    files_to_test = [line.strip()
                                     for line in data if len(line.strip()) > 0]
                except Exception as e:
                    print("There was an error reading the input file [%s]: [%s].\n\t"
                          "Quitting..." % (detections_file, str(e)))
                    sys.exit(1)

                tests = self.get_selected_test_files(
                    files_to_test, folders,   types)
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
                                    "Anomaly", "Hunting", "TTP"],
                                previously_successful_tests: list[str] = []) -> list[str]:

        return self.prune_detections(detection_file_list, types_to_test, previously_successful_tests)

    def get_all_tests_and_detections(self,
                                     folders: list[str] = [
                                         'endpoint', 'cloud', 'network'],
                                     types_to_test: list[str] = [
                                         "Anomaly", "Hunting", "TTP"],
                                     previously_successful_tests: list[str] = []) -> list[str]:
        detections = []
        for folder in folders:
            detections.extend(self.get_all_files_in_folder(
                os.path.join("security_content/detections", folder), "*.yml"))

        # Prune this down to only the subset of detections we can test
        return self.prune_detections(detections, types_to_test, previously_successful_tests)

    def get_all_files_in_folder(self, foldername: str, extension: str) -> list[str]:
        filenames = glob.glob(os.path.join(foldername, extension))
        return filenames

    def get_changed_test_files(self, folders=['endpoint', 'cloud', 'network'],   types_to_test=["Anomaly", "Hunting", "TTP"], previously_successful_tests=[]) -> list[str]:

        branch1 = self.security_content_local_branch
        branch2 = SECURITY_CONTENT_MAIN_BRANCH
        g = git.Git('security_content')
        all_changed_test_files = []

        all_changed_detection_files = []
        if branch1 != SECURITY_CONTENT_MAIN_BRANCH:
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
        

        return self.prune_detections(changed_detection_files,   types_to_test, previously_successful_tests)

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

