import subprocess
import sys
import tarfile
import os
from typing import TextIO
class Build:
    def __init__(self, args):
        base_path = args.path
        if args.product == "ESCU":
            self.source = os.path.join(base_path, "dist","escu")
            self.app_name = "DA-ESS-ContentUpdate"
        elif args.product == "SSA":
            raise(Exception(f"{args.product} build not supported"))
        else:
            self.source = os.path.join(base_path, "dist", args.product)
            self.app_name =  args.product
        if not os.path.exists(self.source):
            raise(Exception(f"Attemping to build app from {self.source}, but it does not exist."))

        print(f"Building Splunk App from source {self.source}")    
        
        
        self.output_dir_base = args.output_dir
        

        self.output_dir_source = os.path.join(self.output_dir_base, self.app_name)

        #self.output_package = os.path.join(self.output_dir_base, self.app_name+'.tar.gz')
        
        self.copy_app_source()
        self.validate_splunk_app()
        self.build_splunk_app()
        #self.archive_splunk_app()
    
    def copy_app_source(self):
        import shutil

        try:
            if os.path.exists(self.output_dir_source):
                print(f"The directory {self.output_dir_source} exists. Deleting it in preparation to build the app... ", end='', flush=True)
                try:
                    shutil.rmtree(self.output_dir_source)
                    print("Done!")
                except Exception as e:
                    raise(Exception(f"Unable to delete {self.output_dir_source}"))
                
            print(f"Copying Splunk App Source to {self.source} in preparation for building...", end='')
            sys.stdout.flush()
            shutil.copytree(self.source, self.output_dir_source, dirs_exist_ok=True)
            print("done")
        except Exception as e:
            raise(Exception(f"Failed to copy Splunk app source from {self.source} -> {self.output_dir_source} : {str(e)}"))
        

    def validate_splunk_app(self):
        proc = "nothing..."
        try:
            print("Validating Splunk App...")
            sys.stdout.flush()
            nothing = subprocess.check_output(["slim", "validate", self.output_dir_source])
            
            print("Package Validation Complete")
        except Exception as e:
            print(f"error: {str(e)} ")
            raise(Exception(f"Error building Splunk App: {str(e)}"))


    def build_splunk_app(self):
        proc = "nothing..."
        try:
            print("Building Splunk App...")
            sys.stdout.flush()
            nothing = subprocess.check_output(["slim", "package", "-o", self.output_dir_base, self.output_dir_source])
            print("Package Generation Complete")
        except Exception as e:
            print("error")
            raise(Exception(f"Error building Splunk App: {str(e)}"))
    
    '''
    def archive_splunk_app(self):
        
        try:
            print(f"Creating Splunk app archive {self.output_package}...", end='')
            sys.stdout.flush()
            with tarfile.open(self.output_package, "w:gz") as tar:
                tar.add(self.output_dir_build, arcname=os.path.basename(self.output_dir_build))
            print("done")
        except Exception as e:
            print("error")
            raise(Exception(f"Error creating {self.output_package}: {str(e)}"))
    '''

    