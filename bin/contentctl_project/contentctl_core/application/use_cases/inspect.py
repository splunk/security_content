import subprocess
class Inspect:
    def __init__(self, args):
        try:
            import splunk_appinspect
        except Exception as e:
            print("Failed to import libmagic.  If you're on macOS, you probably need to run 'brew install libmagic'")
            raise(Exception(f"AppInspect Failed to import magic: str(e)"))
        
        #Splunk appinspect does not have a documented python API... so we run it 
        #used the Command Line interface
        self.path = args.path
        
        proc = "no output produced..."
        try:
            proc = subprocess.check_output(["splunk-appinspect", "inspect", self.path], stderr=subprocess.STDOUT)
        except Exception as e:
            print(f"Appinspect failed with output: \n{proc}")
            raise(Exception(f"Error running appinspect on {self.path}: {str(e)}"))
        
        print(f"Appinspect on {self.path} was successful!")


        
        
        

        

