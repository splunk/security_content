import subprocess
import os
class Inspect:
    def __init__(self, args):
        try:
            import splunk_appinspect
        except Exception as e:
            print("Failed to import libmagic.  If you're on macOS, you probably need to run 'brew install libmagic'")
            raise(Exception(f"AppInspect Failed to import magic: str(e)"))
        

        #Splunk appinspect does not have a documented python API... so we run it 
        #using the Command Line interface
        self.package_path = args.package_path
        
        proc = "no output produced..."
        try:
            proc = subprocess.check_output(["splunk-appinspect", "inspect", self.package_path])
        except Exception as e:
            print(f"Appinspect failed with output: \n{proc}")
            raise(Exception(f"Error running appinspect on {self.package_path}: {str(e)}"))
        
        print(f"Appinspect on {self.package_path} was successful!")


        
        
        

        

