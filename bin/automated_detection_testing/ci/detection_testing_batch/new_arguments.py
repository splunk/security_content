import argparse
import json
from modules import validate_args
import sys


DEFAULT_CONFIG_FILE = "defaults.json"
def main(args):

    try:
        with open(DEFAULT_CONFIG_FILE, 'r') as settings_file:
            default_settings = json.load(settings_file)
    except Exception as e:
        print("Error loading settings file %s: %s"%(DEFAULT_CONFIG_FILE, str(e)), file=sys.stderr)
        sys.exit(1)
    

    parser = argparse.ArgumentParser(
        description="Use 'SOME_PROGRAM_NAME_STRING --help' to get help with the arguments")
    actions_parser = parser.add_subparsers(title="test action")

    configure_parser = actions_parser.add_parser(
        "configure", help="configure a test run")

    configure_parser.add_argument(
        '-o', '--output_config', required=True, help="Name of config file to generate")

    test_parser = actions_parser.add_parser("test", help="run a test")
    test_parser.add_argument('-b', '--branch', required=True,
                             help="The branch whose detections you would like to test.  "\
                                  "In order to calculate new/changed detections, the detections "\
                                  "in this branch will be diffed against those in the 'develop' branch")
    test_parser.add_argument(
        '-pr', '--pull_request_number', required=False, help="Pull request number.")

    VALID_DETECTION_TYPES = ['endpoint', 'cloud', 'network']

    #Common Test Arguments
    test_parser.add_argument('-t', '--types', type=str, action="append", 
                             help="Detection types to test. Can be one or more of %s"%(VALID_DETECTION_TYPES))
    
    
    test_parser.add_argument('-e', '--escu_package', type=argparse.FileType('rb'), required=False, 
                                        help="A previously generated ESCU PAcklage to use.  If you pass this "\
                                             "argument, a new ESCU package will not be generated.  Note that this "\
                                             "may cause newly-written detections to fail (for example, if they "\
                                             "leverage macros that have been added or modified).")
   
    test_parser.add_argument('-p','--persist_security_content', required=False, action="store_true",
                             help="Assumes security_content directory already exists.  Don't check it out and overwrite it again.  Saves "\
                             "time and allows you to test a detection that you've updated.  Runs generate again in case you have "\
                             "updated macros or anything else.  Especially useful for quick, local, iterative testing.")


    test_parser.add_argument('-tag', '--container_tag', required=False, default = default_args['container_tag'], 
                             help="The tag of the Splunk Container to use.  Tags are located "\
                                  "at https://hub.docker.com/r/splunk/splunk/tags")

    test_parser.add_argument("-show", "--show_password", required=False, default=False, action='store_true', 
                             help="Show the generated password to use to login to splunk.  For a CI/CD run, "\
                            "you probably don't want this.")

    test_parser.add_argument('-r','--reuse_image', required=False, default=True, action='store_true', 
                             help="Should existing images be re-used, or should they be redownloaded?")

    test_parser.add_argument('-i', '--interactive_failure', required=False, default=False, action='store_true',
                            help="If a test fails, should we pause before removing data so that the search can be debugged?")
    

    
    #Mode settings
    mode_parser = test_parser.add_subparsers(title="Test Modes", required=True)
    #NEW
    new_parser = mode_parser.add_parser("changes", 
                                        help="Test only the new or changed detections")

    #SELECTED

    selected_parser = mode_parser.add_parser("selected", help="Test only the detections from the target branch that "\
                                                              " are passed on the command line.  These can be given as "\
                                                              "a list of files or as a file containing a list of files.")
    selected_group = selected_parser.add_mutually_exclusive_group(required=True)
    selected_group.add_argument('-df', '--detections_file', type=argparse.FileType('r'), 
                                required=False, help="A file containing a list of detections to run, one per line")
    selected_group.add_argument('-dl', '--detections_list', 
                                required=False, help="The names of files that you want to test, separated by commas.  "\
                                                     "Do not include spaces between the detections!")
    
    #ALL
    all_parser = mode_parser.add_parser("all", 
                                        help="Test all of the detections in the target branch.  "\
                                             "Note that this could take a very long time.")


    args = parser.parse_args()
    try:
        validate_args.validate(args.__dict__)

    except Exception as e:
        print("Error validating command line arguments: [%s]"%(str(e)))
        sys.exit(1)



if __name__ == "__main__":
    main(sys.argv[1:])
