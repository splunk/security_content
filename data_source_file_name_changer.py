import os
import sys
import yaml
import subprocess

def change_file_names(directory):
    if not os.path.isdir(directory):
        print(f"The path {directory} is not a valid directory.")
        return

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.yml') or file.endswith('.yaml'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as yml_file:
                    yml_data = yaml.safe_load(yml_file)
                
                if 'name' in yml_data:
                    new_file_name = yml_data['name'].lower().replace(" ", "_").replace(".", "_").replace("-", "_") + ".yml"
                    new_file_path = os.path.join(root, new_file_name)
                    subprocess.run(['git', 'mv', file_path, new_file_path])
                    print(f"Renamed {file_path} to {new_file_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python data_source_file_name_changer.py <directory>")
    else:
        directory = sys.argv[1]
        change_file_names(directory)
