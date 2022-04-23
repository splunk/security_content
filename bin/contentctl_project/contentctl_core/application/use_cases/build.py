import slim
import sys


class Build:
    def __init__(self, args, source:str = "", output_dir:str = ""):
        try:
            print("Validating Splunkbase App...", end='')
            sys.stdout.flush()
            slim.validate(source=source)
            print("done")
            
            print("Building Splunkbase App...", end='')
            sys.stdout.flush()
            slim.package(source=source, output_dir=output_dir)
            print("done")


        except Exception as e:
            raise(Exception(f"Error building Splunk App: {str(e)}"))

    