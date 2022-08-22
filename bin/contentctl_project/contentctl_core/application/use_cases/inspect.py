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
            proc = subprocess.run(["splunk-appinspect", "inspect", self.package_path])
            if proc.returncode != 0:
                raise(Exception(f"splunk-appinspect failed with return code {proc.returncode}"))
        except Exception as e:
            raise(Exception(f"Error running appinspect on {self.package_path}: {str(e)}"))
        
        print(f"Appinspect on {self.package_path} was successful!")


        
        
        

        

