#!/usr/bin/env python3
"""
Validate response_templates JSON files against the ResponseTemplate schema
defined in mcopenapi_public.yml
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, Tuple

import yaml
from jsonschema import Draft7Validator


def load_openapi_schema(yaml_path: Path, schema_name: str = 'ResponseTemplate', debug: bool = False) -> Dict[str, Any]:
    """Load the OpenAPI YAML file and extract the specified schema."""
    with open(yaml_path, 'r') as f:
        openapi_spec = yaml.safe_load(f)

    # Extract the specified schema
    target_schema = openapi_spec['components']['schemas'][schema_name]

    # Resolve references to other schemas
    schemas = openapi_spec['components']['schemas']

    # We need to build a complete schema by resolving $ref
    def resolve_refs(schema_obj: Any, schemas_dict: Dict) -> Any:
        """Recursively resolve $ref in schema objects."""
        if isinstance(schema_obj, dict):
            if '$ref' in schema_obj:
                # Extract schema name from reference like "#/components/schemas/ResponseTemplatePhase"
                ref_path = schema_obj['$ref'].split('/')[-1]
                return resolve_refs(schemas_dict.get(ref_path, {}), schemas_dict)
            else:
                return {k: resolve_refs(v, schemas_dict) for k, v in schema_obj.items()}
        elif isinstance(schema_obj, list):
            return [resolve_refs(item, schemas_dict) for item in schema_obj]
        else:
            return schema_obj

    resolved_schema = resolve_refs(target_schema, schemas)

    # Add JSON Schema draft version
    resolved_schema['$schema'] = 'http://json-schema.org/draft-07/schema#'

    # Debug: dump resolved schema to file (only once per schema)
    if debug:
        debug_file = Path(f"debug_{schema_name}_schema.json")
        if not debug_file.exists():
            with open(debug_file, 'w') as f:
                json.dump(resolved_schema, f, indent=2)
            print(f"🐛 Debug: Resolved schema dumped to {debug_file}")
        else:
            print(f"🐛 Debug: Resolved schema already exists at {debug_file}")

    return resolved_schema


def validate_json_file(json_path: Path, schema: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate a JSON file against the provided schema.
    Returns (is_valid, error_message)
    """
    try:
        with open(json_path, 'r') as f:
            json_data = json.load(f)

        # Validate against schema
        validator = Draft7Validator(schema)
        errors = sorted(validator.iter_errors(json_data), key=lambda e: e.path)

        if errors:
            error_messages = []
            for error in errors:
                path = '.'.join(str(p) for p in error.path)
                error_messages.append(f"  - Path '{path}': {error.message}")
            return False, '\n'.join(error_messages)

        return True, "Valid"

    except json.JSONDecodeError as e:
        return False, f"JSON parsing error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"


def main():
    parser = argparse.ArgumentParser(
        description="Validate response_templates JSON files against the ResponseTemplate schema"
    )
    parser.add_argument(
        '-d', '--directory',
        type=str,
        default='.',
        help='Directory containing response template JSON files'
    )
    parser.add_argument(
        '-s', '--schema',
        type=str,
        default='mcopenapi_public.yml',
        help='Path to the OpenAPI YAML schema file'
    )
    parser.add_argument(
        '-m', '--manifest',
        type=str,
        help='Path to manifest.json file to validate against ResponseTemplateManifest schema'
    )
    parser.add_argument(
        '--merged-dir',
        type=str,
        help='Directory containing merged response template JSON files to validate against ResponseTemplateMerged schema'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Dump resolved schemas to JSON files for debugging'
    )

    args = parser.parse_args()

    # Resolve paths
    schema_path = Path(args.schema)
    templates_dir = Path(args.directory)

    if not schema_path.exists():
        print(f"❌ Error: Schema file not found: {schema_path}")
        sys.exit(1)

    if not templates_dir.exists():
        print(f"❌ Error: Templates directory not found: {templates_dir}")
        sys.exit(1)

    validation_results = []

    # Validate manifest if provided
    if args.manifest:
        manifest_path = Path(args.manifest)
        if not manifest_path.exists():
            print(f"❌ Error: Manifest file not found: {manifest_path}")
            sys.exit(1)

        print(f"📋 Loading ResponseTemplateManifest schema from {schema_path}")
        try:
            manifest_schema = load_openapi_schema(schema_path, 'ResponseTemplateManifest', debug=args.debug)
            print(f"✅ Manifest schema loaded successfully")
        except Exception as e:
            print(f"❌ Error loading manifest schema: {e}")
            sys.exit(1)

        print(f"\n🔍 Validating manifest file: {manifest_path.name}\n")
        print(f"Validating {manifest_path.name}...", end=" ")
        is_valid, message = validate_json_file(manifest_path, manifest_schema)
        validation_results.append((manifest_path.name, is_valid, message))

        if is_valid:
            print("✅")
        else:
            print("❌")
            print(message)

    # Validate merged response templates if provided
    if args.merged_dir:
        merged_dir = Path(args.merged_dir)
        if not merged_dir.exists():
            print(f"❌ Error: Merged templates directory not found: {merged_dir}")
            sys.exit(1)

        print(f"\n📋 Loading ResponseTemplateMerged schema from {schema_path}")
        try:
            merged_schema = load_openapi_schema(schema_path, 'ResponseTemplateMerged', debug=args.debug)
            print(f"✅ ResponseTemplateMerged schema loaded successfully")
        except Exception as e:
            print(f"❌ Error loading merged schema: {e}")
            sys.exit(1)

        # Find all JSON files in merged directory (excluding manifest.json)
        merged_files = [f for f in merged_dir.glob('*.json')
                       if f.name != 'manifest.json']

        if merged_files:
            print(f"\n🔍 Found {len(merged_files)} merged response template file(s) to validate\n")

            for json_file in sorted(merged_files):
                print(f"Validating {json_file.name}...", end=" ")
                is_valid, message = validate_json_file(json_file, merged_schema)
                validation_results.append((json_file.name, is_valid, message))

                if is_valid:
                    print("✅")
                else:
                    print("❌")
                    print(message)
        else:
            print(f"⚠️  No merged template JSON files found in {merged_dir}")

    # Load ResponseTemplate schema
    print(f"\n📋 Loading ResponseTemplate schema from {schema_path}")
    try:
        schema = load_openapi_schema(schema_path, 'ResponseTemplate', debug=args.debug)
        print(f"✅ ResponseTemplate schema loaded successfully")
    except Exception as e:
        print(f"❌ Error loading schema: {e}")
        sys.exit(1)

    # Find all JSON files (excluding manifest if it's in the same directory)
    json_files = [f for f in templates_dir.glob('*.json')
                  if not (args.manifest and f.name == Path(args.manifest).name)]

    if not json_files:
        if not args.manifest:
            print(f"⚠️  No JSON files found in {templates_dir}")
            sys.exit(0)
    else:
        print(f"\n🔍 Found {len(json_files)} response template file(s) to validate\n")

        # Validate each file
        for json_file in sorted(json_files):
            print(f"Validating {json_file.name}...", end=" ")
            is_valid, message = validate_json_file(json_file, schema)
            validation_results.append((json_file.name, is_valid, message))

            if is_valid:
                print("✅")
            else:
                print("❌")
                print(message)

    # Summary
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)

    passed = sum(1 for _, is_valid, _ in validation_results if is_valid)
    failed = len(validation_results) - passed

    for filename, is_valid, message in validation_results:
        status = "✅ PASS" if is_valid else "❌ FAIL"
        print(f"{status}: {filename}")

    print(f"\nTotal: {len(validation_results)} | Passed: {passed} | Failed: {failed}")

    if failed > 0:
        print("\n❌ Validation failed!")
        sys.exit(1)
    else:
        print("\n✅ All files validated successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()
