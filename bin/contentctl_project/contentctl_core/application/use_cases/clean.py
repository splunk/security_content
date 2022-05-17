import re
import glob
import os

#f-strings cannot include a backslash, so we include this as a constant
NEWLINE_INDENT = "\n\t"
class Initialize:
    def __init__(self, args):
        self.items_scanned = []
        self.items_deleted = []
        self.items_kept = []
        self.items_deleted_failed = []
        self.success = self.remove_all_content()
        
        self.print_results_summary()
        

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
        
        steps = [(self.remove_detections,"Removing Detections"),
                 (self.remove_investigations,"Removing Investigations"),
                 (self.remove_lookups,"Removing Lookups"),
                 (self.remove_macros,"Removing Macros"),
                 (self.remove_notebooks,"Removing Notebooks"),
                 (self.remove_playbooks,"Removing Playbooks"),
                 (self.remove_stories,"Removing Stores"),
                 (self.remove_tests,"Removing Tests"),
                 (self.remove_dist_lookups,"Removing Dist Lookups")]
        
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
        
    

