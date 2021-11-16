import argparse
import sys


def main(args):
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

    mode_parser = test_parser.add_subparsers(title="Test Modes", required=True)
    new_parser = mode_parser.add_parser("new", 
                                        #aliases=['changed'], 
                                        help="Test only the new or changed detections")
    selected_parser = mode_parser.add_parser("selected", help="Test only the detections from the target branch that "\
                                                              " are passed on the command line.  These can be given as "\
                                                              "a list of files or as a file containing a list of files.")
    selected_group = selected_parser.add_mutually_exclusive_group(required=True)
    selected_group.add_argument('-df', '--detections_file', type=argparse.FileType('r'), 
                                required=False, help="A file containing a list of detections to run, one per line")
    selected_group.add_argument('-dl', '--detections_list', 
                                required=False, help="The names of files that you want to test, separated by commas.  "\
                                                     "Do not include spaces between the detections!")
    


    
    all_parser = mode_parser.add_parser("all", 
                                        #aliases=['everything'], 
                                        help="Test all of the detections in the target branch.  "\
                                             "Note that this could take a very long time.")


    parser.parse_args()


if __name__ == "__main__":
    main(sys.argv[1:])
