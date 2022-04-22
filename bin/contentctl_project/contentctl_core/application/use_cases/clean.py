import re
import glob
import os

class Clean:
    def __init__(self, args):
        pass

    def remove_all_content(self)-> bool:
        errors = []
        
        steps = [(self.remove_detections,"Removing Detections"),
                 (self.remove_investigations,"Removing Investigations"),
                 (self.remove_lookups,"Removing Lookups"),
                 (self.remove_macros,"Removing Macros"),
                 (self.remove_notebooks,"Removing Notebooks"),
                 (self.remove_playbooks,"Removing Playbooks"),
                 (self.remove_stories,"Removing Stores"),
                 (self.remove_tests,"Removing Tests")]
        
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
            print(f"Clean failed on the following steps:\n\t{'\n\t'.join(errors)}")
            return False
        
    def remove_detections(self, glob_patterns:list[str]=["detections/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_investigations(self,glob_patterns:list[str]=["investigations/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_lookups(self, glob_patterns:list[str]=["lookups/**/*.yml","lookups/**/*.csv"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_macros(self,glob_patterns:list[str]=["macros/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_notebooks(self, glob_patterns:list[str]=["notesbooks/**/*.ipynb"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_playbooks(self, glob_patterns:list[str]=["playbooks/**/*"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)

    def remove_stories(self, glob_patterns:list[str]=["stories/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)
        
    def remove_tests(self, glob_patterns:list[str]=["tests/**/*.yml"], keep:list[str]=[]) -> bool:
        return self.remove_by_glob_patterns(glob_patterns, keep)
    
    def remove_by_glob_patterns(self, glob_patterns:list[str]=["tests/**/*.yml"], keep:list[str]=[]) -> bool:
        success = True
        for pattern in glob_patterns:
            success |= self.remove_by_glob_pattern(pattern, keep)
        return success
    def remove_by_glob_pattern(self, glob_pattern:str, keep:list[str]) -> bool:
        success = True
        try:
            matched_filenames = glob.glob(glob_pattern)
            for filename in matched_filenames:
                success &= self.remove_file(filename, keep)
            return success
        except Exception as e:
            print(f"Error running glob on the pattern {glob_pattern}: {str(e)}")
            return False

        

    def remove_file(self, filename:str, keep:list[str]) -> bool:        
        for keep_pattern in keep:
            if re.search(keep_pattern, filename) is not None:
                print(f"Preserving file {filename} which conforms to the keep regex {keep_pattern}")
                return True
            
        #File will be deleted - it was not identified as a file to keep
        #Note that, by design, we will not/cannot delete files with os.remove.  We want to keep
        #the folder hierarchy.  If we want to delete folders, we will need to update this library
        try:
            os.remove(filename)
            return True
        except Exception as e:
            print(f"Error deleting file {filename}: {str(e)}")
            return False
        
    

