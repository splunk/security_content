import argparse
import io
import json
import jsonschema_errorprinter


setup_schema = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
                    "enum": ["configure", "test"]
            
        },

        "branch": {
            "type":"string"
        },

        "container_tag": {
            "type": "string"
        },
        
        "interactive_failure": {
            "type": "boolean"
        },

        "local_apps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "local_path": {
                        "type": "string"
                    },
                    "app_name": {
                        "type": "string"
                    },
                    "app_number": {
                        "type": "integer"
                    },
                    "app_version": {
                        "type": "string"
                    }
                }
            }
        },

        "mode": {
            "type":"string",
            "enum": ["changes", "selected", "new"]
        },

        "num_containers": {
            "type": "integer",
            "minimum": 1
        },

        "persist_security_content": {
            "type": "boolean"
        },

        "pr_number": {
            "type":"integer"
        },

        "reuse_image": {
            "type": "boolean"
        },

        "show_password": {
            "type": "boolean"
        },

        "splunkbase_apps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string"
                    },
                    "app_number": {
                        "type": "integer"
                    },
                    "app_version": {
                        "type": "string"
                    },
                    "app_name": {
                        "type": "string"
                    }
                }
            }
        },

        "types": {
            "type": "array",
            "enum": ["endpoint", "cloud", "network"],
            "maxItems": 3,
            "maxItemsssss":2
        },
        

        
        

        

    }
}

import jsonschema
import jsonschema.exceptions
import sys

def v(configuration:dict)->bool:
    #v = jsonschema.Draft201909Validator(argument_schema)
    test = {"action":"tests", "branch":15}
    try:
        validation_results = jsonschema_errorprinter.check_json(test, setup_schema)
        if len(validation_results) == 0:
            print("Input configuration successfully validated!")
            return True
        else:
            print("[%d] failures detected during validation of the configuration!"%(len(validation_results)))
            for error in validation_results:
                print(error,end="\n\n", file=sys.stderr)
            return False            
    except Exception as e:
        print(str(e))
        return False


    '''
    try:
        v.validate({"action":"doot", "branch":"15"}  )
    except jsonschema.exceptions.ValidationError as e:
        print("Error validating the json", file=sys.stderr)
        print(e)
        return False
        
    except jsonschema.exceptions.SchemaError as e:
        print("Error validating the schema", file=sys.stderr)
    '''
if __name__ == "__main__":
    v()
'''
def load(json_settings: io.TextIOWrapper) -> dict:
    default_settings = json.load(json_settings)
    return default_settings


def load_and_validate(json_settings: io.TextIOWrapper) -> dict:
    settings = load(json_settings)
    validate(settings)
    return settings


def validate(args: dict) -> bool:
    validate_common_arguments()

    validate_mode()

    return True


def validate_mode(args: dict) -> bool:
    return True


def validate_mode_selected(args: dict) -> bool:
    return True


def validate_mode_changes(args: dict) -> -bool:
    return True


def validate_mode_all(args: dict) -> bool:
    return True
'''