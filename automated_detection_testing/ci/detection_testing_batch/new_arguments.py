import argparse
import sys


def main(args):

    default_args = {}

    parser = argparse.ArgumentParser(
        description="Use 'SOME_PROGRAM_NAME_STRING --help' to get help with the arguments")
    actions_parser = parser.add_subparsers(title="test action")

    configure_parser = actions_parser.add_parser(
        "configure", help="configure a test run")

    configure_parser.add_argument(
        '-c', '--context', required=True, help="Some help as a test")

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


    test_parser.add_argument('tag', '--container_tag', required=False, default = default_args['container_tag'], 
                             help="The tag of the Splunk Container to use.  Tags are located "\
                                  "at https://hub.docker.com/r/splunk/splunk/tags")

    test_parser.add_argument("-show", "--show_password", required=False, default=False, action='store_true', 
                             help="Show the generated password to use to login to splunk.  For a CI/CD run, "\
                            "you probably don't want this.")

    
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


    a = parser.parse_args()
    
    print(a)
    print(a.__dict__)


if __name__ == "__main__":
    main(sys.argv[1:])
