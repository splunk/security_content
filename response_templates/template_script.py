import argparse
import collections
import json
from pathlib import Path

def generate_manifest(directory, prefix, output_dir):
    # Code to generate the manifest file
    
    response_templates = []
    res = {
        "response_templates": response_templates
    }
    try:
        template_mapping = _get_template_mapping(directory)
        for template_name, template_list in template_mapping.items():
            out_template_name = f"{template_name}.json"

            templates_version= []
            for _, file in template_list:
                with open(file, 'r') as in_file:
                    content = in_file.read()
                    curr_template = json.loads(content)
                    version = curr_template.get("version", "1.0")
                    update_time = curr_template.get("update_time")
                    curr_metadata = {
                        "version": version,
                        "update_time": update_time,
                    }
                    templates_version.append(curr_metadata)
            response_templates.append({
                "name": template_name,
                "versions": templates_version,
                "link": f"{prefix}{out_template_name}"
            })
        
        with open(Path(output_dir) / "manifest.json", 'w') as out_file:
            out_file.write(json.dumps(res))

    except Exception as e:
        print(f"Error during merging files: {e}")
        raise


def _get_template_mapping(directory):
    path = Path(directory)
    if not path.exists() or not path.is_dir():
        raise ValueError(f"The directory {directory} does not exist or is not a directory.")
    
    files = [f for f in path.iterdir() if f.is_file()]
    if not files:
        raise ValueError(f"No files found in the directory {directory} to merge.")
    
    template_to_file_mapping = collections.defaultdict(list)

    for file in files:
        file_name_no_ext= file.name.replace(".json", "")
        name_split = file_name_no_ext.rsplit("_v", 1)
        if len(name_split) != 2:
            print(f"Skipping file {file.name}: does not match expected pattern '<template_name>_v<version>'")
            continue
        template_name = name_split[0]
        version = name_split[1]

        template_to_file_mapping[template_name].append((version, file))
    
    return template_to_file_mapping

def merge_files(directory, output_dir):
    try:
        template_mapping = _get_template_mapping(directory)
        for template_name, template_list in template_mapping.items():
            out_template_name = f"{template_name}.json"

            templates = []
            for _, file in template_list:
                with open(file, 'r') as in_file:
                    content = in_file.read()
                    templates.append(json.loads(content))
            
            with open(Path(output_dir) / out_template_name, 'w') as out_file:
                out_file.write(json.dumps(templates))
    except Exception as e:
        print(f"Error during merging files: {e}")
        raise    

def main():
    parser = argparse.ArgumentParser(description="Response template file merger and manifest generator")

    parser.add_argument('-m', '--manifest', help='Generate a manifest file', action='store_true')
    parser.add_argument('-d', '--directory', help='Directory containing response template files', required=True)
    parser.add_argument('-o', '--output', help='Output directory for merged templates', default='output')
    parser.add_argument('-p', '--prefix', help='SCS prefix', default='https://securitycontent.scs.splunk.com/response_templates/')

    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    merge_files(args.directory, args.output)

    if args.manifest:
        generate_manifest(args.directory, args.prefix, args.output)

if __name__ == "__main__":
    main()