import json
import sys
from pathlib import Path
import yaml
from jsonschema import validate, ValidationError

def read_yaml_file(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def read_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def validate_json_against_schema(json_data, schema):
    try:
        validate(instance=json_data, schema=schema)
        return True
    except ValidationError as e:
        print(f"Validation Error: {e}")
        return False

def main(yaml_file_path, json_schema_file_path):
    yaml_data = read_yaml_file(yaml_file_path)
    json_schema = read_json_file(json_schema_file_path)

    is_valid = validate_json_against_schema(yaml_data, json_schema)

    if is_valid:
        print("The YAML file is valid according to the JSON schema.")
    else:
        print("The YAML file is not valid according to the JSON schema.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python ba_detections_validator.py <yaml_file> <json_schema_file>")
        sys.exit(1)

    yaml_file_path = Path(sys.argv[1])
    json_schema_file_path = Path(sys.argv[2])

    if not yaml_file_path.is_file() or not json_schema_file_path.is_file():
        print("Both input files must exist.")
        sys.exit(1)

    main(yaml_file_path, json_schema_file_path)