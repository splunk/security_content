import argparse
import json
from typing import OrderedDict, Union
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
            choice = input("%s [default: %s | choices: {%s}]: " % (
                arg, default_string, ','.join(schema['properties'][arg]['enum'])))
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
                    # Do nothing
                    pass
                elif choice.isdigit():
                    pass
                else:
                    choice = '"' + choice + '"'

                new_config[arg] = json.loads(choice)
                formatted_print = choice
        # We print out choice instead of new_config[arg] because the json.loads() messes up the quotation marks again
        print("\t{0}\n".format(formatted_print))

    # Now parse the new config and make sure it's good
    validated_new_settings, schema = validate_args.validate_and_write(
        new_config, args.output_config_file, skip_password_accessibility_check=False)
    if validated_new_settings == None:
        print("Could not update settings.\n\tQuitting...", file=sys.stderr)
        sys.exit(1)

    return ("configure", validated_new_settings)


def update_config_with_cli_arguments(args_dict: dict) -> tuple[str, dict]:
    # First load the config file

    settings, _ = validate_args.validate_file(args_dict['config_file'])
    if settings is None:
        print("Failure while processing settings in [%s].\n\tQuitting..." % (
            args_dict['config_file'].name), file=sys.stderr)
        sys.exit(1)

    # Then update it with the values that were passed as command line arguments
    for key, value in args_dict.items():
        if key in settings:
            settings[key] = value

    # Validate again to make sure we didn't break anything
    settings, _ = validate_args.validate(settings,skip_password_accessibility_check=False)
    if settings is None:
        print("Failure while processing updated settings from command line.\n\tQuitting...", file=sys.stderr)
        sys.exit(1)

    return ("run", settings)


def run_action(args) -> tuple[str, dict]:

    config = update_config_with_cli_arguments(args.__dict__)

    return config


def parse(args) -> tuple[str, dict]:
    '''
    try:
        with open(DEFAULT_CONFIG_FILE, 'r') as settings_file:
            default_settings = json.load(settings_file)
    except Exception as e:
        print("Error loading settings file %s: %s"%(DEFAULT_CONFIG_FILE, str(e)), file=sys.stderr)
        sys.exit(1)
    '''

    import os
    # if there is no default config file, then generate one
    if not os.path.exists(DEFAULT_CONFIG_FILE):
        print("No default configuration file [%s] found.  Creating one..." % (
            DEFAULT_CONFIG_FILE))
        with open(DEFAULT_CONFIG_FILE, 'w') as cfg:
            validate_args.validate_and_write({}, cfg, skip_password_accessibility_check=True)

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
                            default=DEFAULT_CONFIG_FILE,
                            help="The config file for the test.  Note that this file "
                            "cannot be changed (except for credentials that can be "
                            "entered on the command line).")

    run_parser.add_argument('-user', '--splunkbase_username', required=False, type=str,
                            help="Username for login to splunkbase.  This is required "
                            "if downloading packages from Splunkbase.  While this can "
                            "be stored in the config file, it is strongly recommended "
                            "to enter it at runtime.")

    run_parser.add_argument('-b', '--branch', required=False, type=str,
                            help="The branch to run the tests on.")

    run_parser.add_argument('-hash', '--commit_hash', required=False, type=str,
                            help="The hash to run the tests on.")

    run_parser.add_argument('-pr', '--pr_number', required=False, type=int,
                            help="The Pull request to run the tests on.")

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
                            help="The password to login to the Splunk Server.  If the config "
                            "file is set to true, it will override the default False for this.  True "
                            "will override the default value in the config file.")

    run_parser.add_argument("-mock", "--mock", required=False,
                            action="store_true",
                            help="Split into multiple configs, don't actually run the tests. If the config "
                            "file is set to true, it will override the default False for this.  True "
                            "will override the default value in the config file.")

    run_parser.add_argument("-n", "--num_containers", required=False, type=int,
                            help="The number of Splunk containers to run or mock")

    run_parser.add_argument("-nif", "--no_interactive_failure", required=False,
                            action="store_true",
                            help="After a detection fails, pause and allow the user to log into "\
                            "the Splunk server to interactively debug the failure.  Wait for the user "\
                            "to hit enter before removing the test data and moving on to the next test.")

    run_parser.add_argument("-i", "--interactive", required=False,
                            action="store_true",
                            help="After a detection runs, pause and allow the user to log into "\
                            "the Splunk server to debug the detection.  Wait for the user "\
                            "to hit enter before removing the test data and moving on to the next test.")

    args = parser.parse_args()


    # Run the appropriate parser
    try:
        # If one of these arguments is not passed on the command line, don't overwrite its config
        # file value with None - keep the config file value
        keys = list(args.__dict__.keys())
        for key in keys:

            # We have to do the check separately because booleans using the --store_true
            # action have an implict default=False value, even if we don't set it. We cannot
            # set their value to something else, like None

            # Don't overwite booleans
            if args.__dict__[key] is False and key in ["show_splunk_app_password", "mock", "no_interactive_failure", "interactive"]:
                del args.__dict__[key]
            # Don't overwrite other values
            elif args.__dict__[key] is None and key in ["splunkbase_username", "branch", "commit_hash",
                                                        "pr_number", "mode", "splunkbase_password",
                                                        "num_containers"]:
                del args.__dict__[key]

        action, settings = args.func(args)

        
        return action, settings
    except Exception as e:
        print("Unknown Error Validating Json Configuration - [%s]" % (str(e)))
        sys.exit(1)

if __name__ == "__main__":
    parse(sys.argv[1:])
