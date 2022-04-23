import slim
import sys
import tarfile
import os
class Build:
    def __init__(self, args):
        self.source = args.path
        self.output_dir = args.output_dir
        self.output_package = self.output_dir+'.tar.gz'
        
        
        self.validate_splunk_app()
        self.build_splunk_app()
        self.archive_splunk_app()
    
    def validate_splunk_app(self):
        try:            
            print("Validating Splunkbase App...", end='')
            sys.stdout.flush()
            slim.validate(source=self.source)
            print("done")
        except Exception as e:
            print("error")
            raise(Exception(f"Error validating Splunk App: {str(e)}"))

    def build_splunk_app(self):
        try:
            print("Building Splunkbase App...", end='')
            sys.stdout.flush()
            slim.package(source=self.source, output_dir=self.output_dir)
            print("done")
        except Exception as e:
            print("error")
            raise(Exception(f"Error building Splunk App: {str(e)}"))
    
    def archive_splunk_app(self):
        
        try:
            print(f"Creating Splunk app archive {self.output_package}...", end='')
            sys.stdout.flush()
            with tarfile.open(self.output_package, "w:gz") as tar:
                tar.add(self.output_dir, arcname=os.path.basename(self.output_dir))
            print("done")
        except Exception as e:
            print("error")
            raise(Exception(f"Error creating {self.output_package}: {str(e)}"))


    