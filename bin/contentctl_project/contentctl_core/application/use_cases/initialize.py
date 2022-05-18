import re
import glob
import os
import copy
import json

APP_CONFIGURATION_FILE = '''
## Splunk app configuration file

[install]
is_configured = false
state = enabled
state_change_requires_restart = false
build = 7313

[triggers]
reload.analytic_stories = simple
reload.usage_searches = simple
reload.use_case_library = simple
reload.correlationsearches = simple
reload.analyticstories = simple
reload.governance = simple
reload.managed_configurations = simple
reload.postprocess = simple
reload.content-version = simple
reload.es_investigations = simple

[launcher]
author = {author}
version = {version}
description = {description}

[ui]
is_visible = true
label      = {label}

[package]
id = {id}
'''

APP_MANIFEST_TEMPLATE = {
  "schemaVersion": "1.0.0", 
  "info": {
    "title": "TEMPLATE_TITLE", 
    "id": {
      "group": None, 
      "name": "TEMPLATE_NAME", 
      "version": "TEMPLATE_VERSION"
    }, 
    "author": [
      {
        "name": "TEMPLATE_AUTHOR_NAME", 
        "email": "TEMPLATE_AUTHOR_EMAIL", 
        "company": "TEMPLATE_AUTHOR_COMPANY"
      }
    ], 
    "releaseDate": None, 
    "description": "TEMPLATE_DESCRIPTION", 
    "classification": {
      "intendedAudience": None, 
      "categories": [], 
      "developmentStatus": None
    }, 
    "commonInformationModels": None, 
    "license": {
      "name": None, 
      "text": None, 
      "uri": None
    }, 
    "privacyPolicy": {
      "name": None, 
      "text": None, 
      "uri": None
    }, 
    "releaseNotes": {
      "name": None, 
      "text": "./README.md", 
      "uri": None
    }
  }, 
  "dependencies": None, 
  "tasks": None, 
  "inputGroups": None, 
  "incompatibleApps": None, 
  "platformRequirements": None
}

#f-strings cannot include a backslash, so we include this as a constant
NEWLINE_INDENT = "\n\t"
class Initialize:
    def __init__(self, args):
        self.items_scanned = []
        self.items_deleted = []
        self.items_kept = []
        self.items_deleted_failed = []
        
        self.path = args.path
        
        #Information that will be used for generation of a custom manifest
        self.app_title = args.title
        self.app_name = args.name
        self.app_version = args.version
        self.app_description = args.description
        self.app_author_name = args.author_name
        self.app_author_email = args.author_email
        self.app_author_company = args.author_company
        self.app_description = args.description
        self.generate_custom_manifest()
        self.generate_app_configuration_file()
        
        self.success = self.remove_all_content()
        
        self.print_results_summary()
        
        
        
    def generate_app_configuration_file(self):

        
        new_configuration = APP_CONFIGURATION_FILE.format(author = self.app_author_company, 
                                                          version=self.app_version, 
                                                          description=self.app_description, 
                                                          label=self.app_title, 
                                                          id=self.app_name)
        print("format done")
        app_configuration_file_path = os.path.join(self.path, "default", "app.conf")
        try:
            if not os.path.exists(os.path.dirname(app_configuration_file_path)):
                os.makedirs(os.path.dirname(app_configuration_file_path), exist_ok = True)

            with open(app_configuration_file_path, "w") as app_config:
                app_config.write(new_configuration)
        except Exception as e:
            raise(Exception(f"Error writing config to {app_configuration_file_path}: {str(e)}"))
        print(f"Created Custom App Configuration at: {app_configuration_file_path}")
        
        
    def generate_custom_manifest(self):
        #Set all the required fields
        new_manifest = copy.copy(APP_MANIFEST_TEMPLATE)
        try:
            new_manifest['info']['title'] = self.app_title
            new_manifest['info']['id']['name'] = self.app_name
            new_manifest['info']['id']['version'] = self.app_version
            new_manifest['info']['author'][0]['name'] = self.app_author_name
            new_manifest['info']['author'][0]['email'] = self.app_author_email
            new_manifest['info']['author'][0]['company'] = self.app_author_company
            new_manifest['info']['description'] = self.app_description
        except Exception as e:
            raise(Exception(f"Failure setting field to generate custom manifest: {str(e)}"))

        #Output the new manifest file
        manifest_path = os.path.join(self.path, "app.manifest") 
        
        try:
            if not os.path.exists(os.path.dirname(manifest_path)):
                os.makedirs(os.path.dirname(manifest_path), exist_ok = True)

            with open(manifest_path, 'w') as manifest_file:
                json.dump(new_manifest, manifest_file, indent=3)
            
        except Exception as e:
            raise(Exception(f"Failure writing manifest file {manifest_path}: {str(e)}"))

        print(f"Created Custom App Manifest at     : {manifest_path}")

    def print_results_summary(self):
        if self.success is True:
            print("repo has been initialized successfully!\n"
                  "Ready for your custom constent!")
        else:
            print("**Failure(s) initializing repo - check log for details**")
        print(f"Summary:"
              f"\n\tItems Scanned  : {len(self.items_scanned)}"
              f"\n\tItems Kept     : {len(self.items_kept)}"
              f"\n\tItems Deleted  : {len(self.items_deleted)}"
              f"\n\tDeletion Failed: {len(self.items_deleted_failed)}"
        )

    def remove_all_content(self)-> bool:
        errors = []
        
        #List out all the steps we will have to take
        steps = [(self.remove_detections,"Removing Detections"),
                 (self.remove_baselines,"Removing Baselines"),
                 (self.remove_investigations,"Removing Investigations"),
                 (self.remove_lookups,"Removing Lookups"),
                 (self.remove_macros,"Removing Macros"),
                 (self.remove_notebooks,"Removing Notebooks"),
                 (self.remove_playbooks,"Removing Playbooks"),
                 (self.remove_stories,"Removing Stores"),
                 (self.remove_tests,"Removing Tests"),
                 (self.remove_dist_lookups,"Removing Dist Lookups")]
        #Sort the steps so they are performced alphabetically
        steps.sort(key=lambda name: name[1])
        
        for func, text in steps:
            print(f"{text}...",end='')
            success = func()
            if success is True:
                print("done")
            else:
                print("**ERROR!**")
                errors.append(f"Error(s) in {func.__name__}")
            
            

        if len(errors) == 0:
            return True
        else:
            print(f"Clean failed on the following steps:{NEWLINE_INDENT}{NEWLINE_INDENT.join(errors)}")
            return False

    def remove_baselines(self, glob_patterns:list[str]=["baselines/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_dist_lookups(self, glob_patterns:list[str]=["dist/escu/lookups/**/*.yml","dist/escu/lookups/**/*.csv", "dist/escu/lookups/**/*.*"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_detections(self, glob_patterns:list[str]=["detections/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_investigations(self,glob_patterns:list[str]=["investigations/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_lookups(self, glob_patterns:list[str]=["lookups/**/*.yml","lookups/**/*.csv", "lookups/**/*.*"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_macros(self,glob_patterns:list[str]=["macros/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_notebooks(self, glob_patterns:list[str]=["notesbooks/**/*.ipynb"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_playbooks(self, glob_patterns:list[str]=["playbooks/**/*.*"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_stories(self, glob_patterns:list[str]=["stories/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_tests(self, glob_patterns:list[str]=["tests/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)
    
    def remove_by_glob_patterns(self, glob_patterns:list[str], keep:list[str]=[]) -> bool:
        success = True
        for pattern in glob_patterns:
            success |= self.remove_by_glob_pattern(pattern, keep)
        return success
    def remove_by_glob_pattern(self, glob_pattern:str, keep:list[str]) -> bool:
        success = True
        try:
            matched_filenames = glob.glob(glob_pattern, recursive=True)
            for filename in matched_filenames:
                self.items_scanned.append(filename)
                success &= self.remove_file(filename, keep)
            return success
        except Exception as e:
            print(f"Error running glob on the pattern {glob_pattern}: {str(e)}")
            return False

        

    def remove_file(self, filename:str, keep:list[str]) -> bool:        
        for keep_pattern in keep:
            if re.search(keep_pattern, filename) is not None:
                print(f"Preserving file {filename} which conforms to the keep regex {keep_pattern}")
                self.items_kept.append(filename)
                return True
            
        #File will be deleted - it was not identified as a file to keep
        #Note that, by design, we will not/cannot delete files with os.remove.  We want to keep
        #the folder hierarchy.  If we want to delete folders, we will need to update this library
        try:
            os.remove(filename)
            self.items_deleted.append(filename)
            return True
        except Exception as e:
            print(f"Error deleting file {filename}: {str(e)}")
            self.items_deleted_failed.append(filename)
            return False
        
    

