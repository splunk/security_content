import os
import re

# Directory containing YAML files
directory_path = "/Users/bpatel/Research/malware/splunk_github/security_content/detections"

# Iterate through each file in the directory and its subdirectories
for dirpath, dirnames, filenames in os.walk(directory_path):
    for filename in filenames:
        if filename.endswith('.yml'):
            filepath = os.path.join(dirpath, filename)

            # Open and read the YAML file as text
            with open(filepath, 'r') as f:
                content = f.read()

            # Check if the data source contains "Powershell 4104"
            if "`sysmon`" in content:
                # print(type(content))

                pattern1 = r'\bComputer\b'
                pattern2 = r'$Computer\$'
                pattern3 = r'\| rename dest as dest'
                r1 = 'dest'
                r2 = '$dest$'
                r3 = ''

                content = re.sub(pattern1, r1, content)
                content = re.sub(pattern2, r2, content)
                content = re.sub(pattern3, r3, content)

                # # Add `| windows_rename_to_cim` before `| stats`
                # content = content.replace('Computer ', 'dest')
                # content = content.replace('$Computer$', '$dest$')
                # content = content.replace('$Computer$', '$dest$')

                # # In the `| stats` command, rename Computer to dest and UserID to user
                # content = content.replace('by EventCode ScriptBlockText Computer UserID', 
                #                           'by EventCode ScriptBlockText dest user')

                # # Update the observable section
                # content = content.replace('name: Computer', 'name: dest')
                # content = content.replace('name: UserID', 'name: user')

                # # Update the required_fields section
                # content = content.replace('- Computer\n', '- dest\n')
                # content = content.replace('- UserID\n', '- user\n')

                # Write the modified content back to the YAML file
                with open(filepath, 'w') as f:
                    f.write(content)

print("Finished updating YAML files.")