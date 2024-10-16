import os
import yaml
from collections import OrderedDict

# Custom YAML loader to preserve the order of keys
class OrderedLoader(yaml.SafeLoader):
    pass

def construct_mapping(loader, node):
    loader.flatten_mapping(node)
    return OrderedDict(loader.construct_pairs(node))

OrderedLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_mapping
)

# Custom YAML dumper to preserve the order of keys
class OrderedDumper(yaml.SafeDumper):
    pass

def dict_representer(dumper, data):
    return dumper.represent_dict(data.items())

OrderedDumper.add_representer(OrderedDict, dict_representer)

# Define the paths
log_file_path = 'data_source_validation.log'
data_sources_dir = 'data_sources'

# Read the log file to find version mismatches
with open(log_file_path, 'r') as log_file:
    log_lines = log_file.readlines()

# Parse the log file to find the TA name and the latest version
for i, line in enumerate(log_lines):
    if 'Version mismatch' in line:
        ta_name = log_lines[i].split("'")[3].strip()
        latest_version = log_lines[i + 1].split(':')[1].strip()
        print(f"Found version mismatch for TA: {ta_name}, updating to version: {latest_version}")

        # Update the YAML files in the data sources directory
        for filename in os.listdir(data_sources_dir):
            if filename.endswith('.yml'):
                file_path = os.path.join(data_sources_dir, filename)
                with open(file_path, 'r') as yml_file:
                    data = yaml.load(yml_file, Loader=OrderedLoader)

                # Check if the TA name matches and update the version
                updated = False
                for ta in data.get('supported_TA', []):
                    if ta['name'] == ta_name:
                        if ta['version'] != latest_version:
                            ta['version'] = latest_version
                            updated = True

                # Write the updated data back to the YAML file
                if updated:
                    with open(file_path, 'w') as yml_file:
                        yaml.dump(data, yml_file, Dumper=OrderedDumper)

print("Version updates completed.")