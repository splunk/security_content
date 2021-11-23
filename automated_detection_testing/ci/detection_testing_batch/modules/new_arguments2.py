import argparse
import copy
import datetime
import json
from typing import OrderedDict, Union
#import modules.validate_args as validate_args
from modules import validate_args
import sys

DEFAULT_CONFIG_FILE = "test_config.json"

def configure_action(args) -> tuple[str, dict]:
    settings = OrderedDict()
    if args.input_config_file is None:
        settings, schema = validate_args.validate({})
    else:
        settings, schema = validate_args.validate_file(args.input_config_file)

    if settings is None:
        print("Failure while processing settings\n\tQuitting...", file=sys.stderr)
        sys.exit(1)

    new_config = {}
    for arg in settings:
        default = settings[arg]
        default_string = str(default).replace("'", '"')
        
        if 'enum' in schema['properties'][arg]:
            choice = input("%s [default: %s | choices: {%s}]: " % (arg, default_string,','.join(schema['properties'][arg]['enum'])))
        else:
            choice = input("%s [default: %s]: " % (arg, default_string))
        choice = choice.strip()
        if len(choice) == 0:
            print("\tNothing entered, using default:")
            new_config[arg] = default
            formatted_print = default
        else:
            if choice.lower() in ["true", "false"] and schema['properties'][arg]['type'] == "boolean":
                new_config[arg] = json.loads(choice.lower())
                formatted_print = choice.lower()
            else:

                if choice in ['true', 'false'] or (choice.isdigit() and schema['properties'][arg]['type'] != "integer"):
                    choice = '"' + choice + '"'
                # replace all single quotes with doubles quotes to make valid json
                elif "'" in choice:
                    print('''Found %d single quotes (') in input... we will convert these to double quotes (") to ensure valida json.''' % (
                        choice.count("'")))
                    choice = choice.replace("'", '"')
                elif '"' in choice:
                    #Do nothing
                    pass
                elif choice.isdigit():
                    pass
                else:
                    choice = '"' + choice + '"'

                new_config[arg] = json.loads(choice)
                formatted_print = choice
        #We print out choice instead of new_config[arg] because the json.loads() messes up the quotation marks again
        print("\t{0}\n".format(formatted_print))

    # Now parse the new config and make sure it's good
    validated_new_settings, schema = validate_args.validate_and_write(new_config, args.output_config_file)
    if validated_new_settings == None:        
        print("Could not update settings.\n\tQuitting...", file=sys.stderr)
        sys.exit(1)
    

    return ("configure", validated_new_settings)


def update_config_with_cli_arguments(args_dict:dict)->tuple[str, dict]:
    #First load the config file

    settings,_ = validate_args.validate_file(args_dict['config_file'])
    if settings is None:
        print("Failure while processing settings in [%s].\n\tQuitting..."%(args_dict['config_file'].name), file=sys.stderr)
        sys.exit(1)
    
    #Then update it with the values that were passed as command line arguments
    for key, value in args_dict.items():
        if key in settings:
            settings[key] = value
    
    #Validate again to make sure we didn't break anything
    settings,_ = validate_args.validate(settings)
    if settings is None:
        print("Failure while processing updated settings from command line.\n\tQuitting...", file=sys.stderr)
        sys.exit(1)
    
    now = datetime.datetime.now()
    configname = now.strftime('%Y-%m-%dT%H:%M:%S.%f%z') + '-test-run.json' 
    with open(configname,'w') as test_config:
        settings_with_creds_stripped = copy.deepcopy(settings)
        #strip out credentials
        settings_with_creds_stripped['splunkbase_password'] = None
        settings_with_creds_stripped['splunkbase_username'] = None
        settings_with_creds_stripped['container_password'] = None
        validate_args.validate_and_write(settings_with_creds_stripped, test_config)

    return ("run", settings)

    

def run_action(args) -> tuple[str,dict]:

    config = update_config_with_cli_arguments(args.__dict__)


    return config


def parse(args)->tuple[str,dict]:
    '''
    try:
        with open(DEFAULT_CONFIG_FILE, 'r') as settings_file:
            default_settings = json.load(settings_file)
    except Exception as e:
        print("Error loading settings file %s: %s"%(DEFAULT_CONFIG_FILE, str(e)), file=sys.stderr)
        sys.exit(1)
    '''

    import os
    #if there is no default config file, then generate one
    if not os.path.exists(DEFAULT_CONFIG_FILE):
        print("No default configuration file [%s] found.  Creating one..."%(DEFAULT_CONFIG_FILE))
        with open(DEFAULT_CONFIG_FILE,'w') as cfg:
            validate_args.validate_and_write({},cfg)


    parser = argparse.ArgumentParser(
        description="Use 'SOME_PROGRAM_NAME_STRING --help' to get help with the arguments")
    parser.set_defaults(func=lambda _: parser.print_help())

    actions_parser = parser.add_subparsers(title="Action")

    # Configure parser
    configure_parser = actions_parser.add_parser(
        "configure", help="Configure a test run")
    configure_parser.set_defaults(func=configure_action)
    configure_parser.add_argument('-i', '--input_config_file', required=False,
                                  type=argparse.FileType('r'), help="The config file to base the configuration off of.")
    configure_parser.add_argument('-o', '--output_config_file', required=False, default=DEFAULT_CONFIG_FILE, 
                                  type=argparse.FileType('w'), help="The config file to write the configuration off of.")

    # Run parser
    run_parser = actions_parser.add_parser(
        "run", help="Run a test")
    run_parser.set_defaults(func=run_action)
    run_parser.add_argument('-c', '--config_file', required=False,
                            type=argparse.FileType('r'),
                            default = DEFAULT_CONFIG_FILE,
                            help="The config file for the test.  Note that this file "\
                            "cannot be changed (except for credentials that can be "\
                            "entered on the command line).")

    

    run_parser.add_argument('-user', '--splunkbase_username', required=False, type=str,
                            help="Username for login to splunkbase.  This is required "
                            "if downloading packages from Splunkbase.  While this can "
                            "be stored in the config file, it is strongly recommended "
                            "to enter it at runtime.")

    run_parser.add_argument('-b', '--branch', required=False, type=str,
                            help="The branch to run the tests on.")
    
    run_parser.add_argument('-m', '--mode', required=False, type=str,
                            help="The mode all, changes, or selected for the testing.")

    run_parser.add_argument('-pass', '--splunkbase_password', required=False, type=str,
                            help="Password for login to splunkbase.  This is required if "
                            "downloading packages from Splunkbase.  While this can be "
                            "stored in the config file, it is strongly recommended "
                            "to enter it at runtime.")

    run_parser.add_argument('-splunkpass', '--splunk_app_password', required=False, type=str,
                            help="Password for login to the splunk app.  If you don't "
                            "provide one here or in the config, it will be generated "
                            "automatically for you.")

    run_parser.add_argument("-show_pass", "--show_splunk_app_password", required=False,
                            action="store_true",
                            help="The password to login to the Splunk Server.  If the config "\
                            "file is set to true, it will override the default False for this.  True "\
                            "will override the default value in the config file.")
    
    run_parser.add_argument("-mock", "--mock", required=False, 
                            action="store_true",
                            help="Split into multiple configs, don't actually run the tests. If the config "\
                            "file is set to true, it will override the default False for this.  True "\
                            "will override the default value in the config file.")

    run_parser.add_argument("-n", "--num_containers", required=False, type=int,
                            help="The number of Splunk containers to run or mock")
    
    
    args = parser.parse_args()
    
    
    
    # Run the appropriate parser
    try:
        #If an argument is not passed on the command line, don't overwrite its config 
        #file value with None - keep the config file value
        keys = list(args.__dict__.keys())
        for key in keys:
            if args.__dict__[key] is None and key in ["show_pass", "mock", "mode"]:
                del args.__dict__[key]

        action, settings = args.func(args)
        
        '''
        default_settings,_ = validate_args.validate({})
        if default_settings is None:
            print("Somehow default settings were None.\n\tQuitting...",file=sys.stderr)
            sys.exit(1)
        #Fix up the show_app_password and mock arguments, as shown in the documentation
        #for those args
        settings['show_splunk_app_password'] |= default_settings['show_splunk_app_password']
        settings['mock'] |= default_settings['mock']
        '''
        return action, settings
    except Exception as e:
        print("Unknown Error - [%s]" % (str(e)))
        sys.exit(1)

    '''

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
    '''


if __name__ == "__main__":
    parse(sys.argv[1:])
