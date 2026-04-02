"""
Response template merger and manifest generator for CI/CD pipelines.

This script processes versioned response template JSON files (named <template>_v<version>.json),
merges multiple versions of the same template into single files, and generates a manifest.json
that catalogs all templates with their version metadata and SCS download links.
Used during the build process to prepare templates for deployment.

Example usage:
    # Merge templates only (from repo root)
    python .github/workflows/response_templates/template_script.py -d response_templates/ -o output/

    # Merge templates and generate manifest
    python .github/workflows/response_templates/template_script.py -d response_templates/ -o output/ -m

    # Custom SCS prefix for manifest links
    python .github/workflows/response_templates/template_script.py -d response_templates/ -o output/ -m -p https://custom.url/templates/
"""
import argparse
import collections
import json
import urllib.parse
from pathlib import Path

def _get_out_template_name(template_name):
    return f"{urllib.parse.quote(template_name)}.json"

def generate_manifest(template_mapping, prefix, output_dir):
    # Code to generate the manifest file

    response_templates = []
    res = {
        "response_templates": response_templates
    }
    try:
        for template_name, template_list in sorted(template_mapping.items(), key=lambda x: x[0]):
            out_template_name = _get_out_template_name(template_name)
            curr_template_name = template_name

            templates_version= []
            for _, file in template_list:
                with open(file, 'r') as in_file:
                    content = in_file.read()
                    curr_template = json.loads(content)
                    version = curr_template.get("version")
                    update_time = curr_template.get("update_time")
                    description = curr_template.get("description")
                    curr_template_name = curr_template.get("name", template_name)
                    curr_metadata = {
                        "version": version,
                        "update_time": update_time,
                        "description": description,
                    }
                    templates_version.append(curr_metadata)
            response_templates.append({
                "name": curr_template_name,
                "versions": templates_version,
                "link": f"{prefix}{out_template_name}"
            })

        with open(Path(output_dir) / "manifest.json", 'w') as out_file:
            out_file.write(json.dumps(res, indent=2))

    except Exception as e:
        print(f"Error during merging files: {e}")
        raise


def _get_template_mapping(directory):
    path = Path(directory)
    if not path.exists() or not path.is_dir():
        raise ValueError(f"The directory {directory} does not exist or is not a directory.")

    # Check for non-JSON files (ignore hidden files like .DS_Store)
    non_json_files = [f.name for f in path.iterdir() if f.is_file() and f.suffix != '.json' and not f.name.startswith('.')]
    if non_json_files:
        raise ValueError(f"Non-JSON files found in directory {directory}: {', '.join(non_json_files)}")

    files = [f for f in path.glob("*.json") if f.is_file()]
    if not files:
        raise ValueError(f"No files found in the directory {directory} to merge.")

    template_to_file_mapping = collections.defaultdict(list)

    for file in files:
        with open(file, 'r') as in_file:
            try:
                content = in_file.read()
                template_json = json.loads(content)
                template_name = template_json.get("name")
                version = template_json.get("version")
                if not template_name or not version:
                    raise ValueError(f"File {file.name} is missing required 'name' or 'version' fields in JSON content.")
                template_to_file_mapping[template_name].append((version, file))
            except json.JSONDecodeError as e:
                raise ValueError(f"File {file.name} contains invalid JSON: {e}")

    # Sort each template's version list by version number (ascending order)
    for template_name in template_to_file_mapping:
        try:
            template_to_file_mapping[template_name].sort(key=lambda x: int(x[0]))
        except ValueError:
            raise ValueError(f"Template '{template_name}' has invalid version(s) that cannot be converted to integer")

    return template_to_file_mapping

def merge_files(template_mapping, output_dir):
    try:
        for template_name, template_list in sorted(template_mapping.items(), key=lambda x: x[0]):
            out_template_name = _get_out_template_name(template_name)

            templates = []
            for _, file in template_list:
                with open(file, 'r') as in_file:
                    content = in_file.read()
                    templates.append(json.loads(content))

            with open(Path(output_dir) / out_template_name, 'w') as out_file:
                out_file.write(json.dumps(templates, indent=2))
    except Exception as e:
        print(f"Error during merging files: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(description="Response template file merger and manifest generator")

    parser.add_argument('-m', '--manifest', help='Generate a manifest file', action='store_true')
    parser.add_argument('-d', '--directory', help='Directory containing response template files', required=True)
    parser.add_argument('-o', '--output', help='Output directory for merged templates', default='output')
    parser.add_argument('-p', '--prefix', help='SCS prefix', default='https://securitycontent.scs.splunk.com/response_templates/') # playground endpoint for testing purpose

    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)

    template_mapping = _get_template_mapping(args.directory)

    merge_files(template_mapping, args.output)

    if args.manifest:
        generate_manifest(template_mapping, args.prefix, args.output)

if __name__ == "__main__":
    main()