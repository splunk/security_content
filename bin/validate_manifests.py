#!/usr/bin/python
'''
Take the manifest files and build files for Enterprise Security
'''
import glob
import json
import jsonschema
import sys
import argparse
from os import path

# HIGH Level Fields
STORY_CATEGORIES = [
    "Abuse", "Adversary Tactics", "Best Practices",
    "Cloud Security", "Malware", "Vulnerability"
]

VALID_SEARCH_TYPES = [
    "detection", "investigative", "contextual", "support"
]

VALID_DATA_MODELS = [
    "Alerts",
    "Application_State",
    "Authentication",
    "Certificates",
    "Change_Analysis",
    "Email",
    "Identity_Management",
    "Network_Resolution",
    "Network_Traffic",
    "Vulnerabilities",
    "Web",
    "Network_Sessions",
    "Updates",
    "Risk",
    "Endpoint"]

RISK_OBJECCT_TYPE = [
    "system", "user", "other"
]

PROVIDING_TECHNOLOGIES = [
    "Apache", "Bro", "Microsoft Windows", "Linux", "macOS",
    "Netbackup", "Splunk Enterprise", "Splunk Enterprise Security",
    "Splunk Stream", "Active Directory", "Bluecoat",
    "Carbon Black Response", "Carbon Black Protect", "CrowdStrike Falcon",
    "Microsoft Exchange", "Nessus", "Palo Alto Firewall", "Qualys",
    "Sysmon", "Tanium", "Ziften", "AWS", "OSquery"
]

KILL_CHAIN_PHASES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command and Control", "Actions on Objectives"
]

CIS_CONTROLS = [
    "CIS 1", "CIS 2", "CIS 3", "CIS 4", "CIS 5", "CIS 6", "CIS 7", "CIS 8",
    "CIS 9", "CIS 10", "CIS 11", "CIS 12", "CIS 13", "CIS 14", "CIS 15",
    "CIS 16", "CIS 17", "CIS 18", "CIS 19", "CIS 20"
]

NIST_FIELDS = [
    "ID.AM", "ID.RA", "PR.DS", "PR.IP", "PR.AC", "PR.PT", "PR.AT", "PR.MA",
    "DE.CM", "DE.DP", "DE.AE", "RS.MI", "RS.AN", "RS.RP", "RS.IM", "RS.CO",
    "RC.IM", "RC.CO"
]

MITRE_ATTACK_FIELDS = [
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Authentication Package",
    "Execution",
    "Collection",
    "Exfiltration",
    "Command and Control",
    "Accessibility Features",
    "Account Discovery",
    "AppInit DLLs",
    "Application Deployment Software",
    "Application Shimming",
    "Application Window Discovery",
    "Audio Capture",
    "Automated Collection",
    "Automated Exfiltration",
    "Basic Input/Output System",
    "Binary Padding",
    "Bootkit",
    "Brute Force",
    "Bypass User Account Control",
    "Change Default File Association",
    "Clipboard Data",
    "Code Signing",
    "Command-Line Interface",
    "Commonly Used Port",
    "Communication Through Removable Media",
    "Component Firmware",
    "Component Object Model Hijacking",
    "Connection Proxy",
    "Credential Dumping",
    "Credential Manipulation",
    "Credentials in Files",
    "Custom Command and Control Protocol",
    "Custom Cryptographic Protocol",
    "DLL Injection",
    "DLL Search Order Hijacking",
    "DLL Side-Loading",
    "Data Compressed",
    "Data Encrypted",
    "Data Obfuscation",
    "Data Staged",
    "Data Transfer Size Limits",
    "Data from Local System",
    "Data from Network Shared Drive",
    "Data from Removable Media",
    "Disabling Security Tools",
    "Email Collection",
    "Execution through API",
    "Exfiltration Over Alternative Protocol",
    "Exfiltration Over Command and Control Channel",
    "Exfiltration Over Other Network Medium",
    "Exfiltration Over Physical Medium",
    "Exploitation of Vulnerability",
    "Fallback Channels",
    "File Deletion",
    "File System Logical Offsets",
    "File System Permissions Weakness",
    "File and Directory Discovery",
    "Graphical User Interface",
    "Hypervisor",
    "Indicator Blocking",
    "Indicator Removal from Tools",
    "Indicator Removal on Host",
    "Input Capture",
    "InstallUtil",
    "Legitimate Credentials",
    "Local Network Configuration Discovery",
    "Local Network Connections Discovery",
    "Local Port Monitor",
    "Logon Scripts",
    "MSBuild",
    "Masquerading",
    "Modify Existing Service",
    "Modify Registry",
    "Multi-Stage Channels",
    "Multiband Communication",
    "Multilayer Encryption",
    "NTFS Extended Attributes",
    "Network Service Scanning",
    "Network Share Connection Removal",
    "Network Sniffing",
    "New Service",
    "Obfuscated Files or Information",
    "Pass the Hash",
    "Pass the Ticket",
    "Path Interception",
    "Peripheral Device Discovery",
    "Permission Groups Discovery",
    "PowerShell",
    "Process Discovery",
    "Process Hollowing",
    "Query Registry",
    "Redundant Access",
    "Registry Run Keys / Start Folder",
    "Regsvcs/Regasm",
    "Regsvr32",
    "Remote Desktop Protocol",
    "Create Account",
    "Remote File Copy",
    "Remote Services",
    "Remote System Discovery",
    "Replication Through Removable Media",
    "Rootkit",
    "Rundll32",
    "Scheduled Task",
    "Scheduled Transfer",
    "Screen Capture",
    "Scripting",
    "Security Software Discovery",
    "Security Support Provider",
    "Service Execution",
    "Service Registry Permissions Weakness",
    "Shared Webroot",
    "Shortcut Modification",
    "Software Packing",
    "Standard Application Layer Protocol",
    "Standard Cryptographic Protocol",
    "Standard Non-Application Layer Protocol",
    "System Information Discovery",
    "System Owner/User Discovery",
    "System Service Discovery",
    "System Time Discovery",
    "Taint Shared Content",
    "Third-party Software",
    "Timestomp",
    "Two-Factor Authentication Interception",
    "Uncommonly Used Port",
    "Video Capture",
    "Valid Accounts",
    "Web Service",
    "Web Shell",
    "Windows Admin Shares",
    "Windows Management Instrumentation Event Subscription",
    "Windows Management Instrumentation",
    "Windows Remote Management",
    "Winlogon Helper DLL",
    "Initial Access",
    "Exploitation for Privilege Escalation"]

ALL_UUIDS = []


def validate_search_manifest(search):
    '''Confirmsearch has the required fields for savedsearches.conf'''
    errors = []
    if search['search_id'] == '':
        errors.append('ERROR: Blank Search ID')

    if search['search_id'] in ALL_UUIDS:
        errors.append('ERROR: Duplicate UUID found: %s' % search['search_id'])
    else:
        ALL_UUIDS.append(search['search_id'])

    if search['search_name'].endswith(" "):
        errors.append(
            "ERROR: Search name has trailing spaces: '%s'" %
            search['search_name'])

    if search['search_type'] not in VALID_SEARCH_TYPES:
        errors.append("ERROR: Invalid search type: %s" % search['search_type'])

    if 'mappings' in search:
        if 'kill_chain_phases' in search['mappings']:
            for kill_chain in search['mappings']['kill_chain_phases']:
                if kill_chain not in KILL_CHAIN_PHASES:
                    errors.append(
                        'ERROR: Invalid kill chain phase: %s' %
                        kill_chain)

        if 'cis20' in search['mappings']:
            for cis in search['mappings']['cis20']:
                if cis not in CIS_CONTROLS:
                    errors.append('ERROR: Invalid CIS field: %s' % cis)

        if 'mitre_attack' in search['mappings']:
            for attack in search['mappings']['mitre_attack']:
                if attack not in MITRE_ATTACK_FIELDS:
                    errors.append('ERROR: Invalid ATT&CK label %s' % attack)

        if 'nist' in search['mappings']:
            for nist in search['mappings']['nist']:
                if nist not in NIST_FIELDS:
                    errors.append('ERROR: Invalid nist label %s' % nist)

    if 'data_models' in search['data_metadata']:
        for data_model in search['data_metadata']['data_models']:
            if data_model not in VALID_DATA_MODELS:
                errors.append('ERROR: Invalid data model: %s' % data_model)

            if data_model not in search['search']:
                errors.append(
                    'WARNING: Data model listed but is not in search: %s' %
                    data_model)

    if 'providing_technologies' in search['data_metadata']:
        for providing_technology in \
                search['data_metadata']['providing_technologies']:
            if providing_technology not in PROVIDING_TECHNOLOGIES:
                errors.append(
                    'ERRORS: Unknown product in providing technologies: %s' %
                    providing_technology)

    if search['search_type'] == 'detection':
        try:
            if search['correlation_rule']['risk']:
                for risk_object_type in \
                        search['correlation_rule']['risk']['risk_object_type']:
                    if risk_object_type not in RISK_OBJECCT_TYPE:
                        errors.append(
                            'ERRORS: Unknown risk object type, must be system, \
                                    user, or other got: %s' %
                            risk_object_type)
        except BaseException:
            errors.append('WARNING: correlation_rule is missing risk object')

    if 'providing_technologies' in search['data_metadata']:
        for providing_technology in \
                search['data_metadata']['providing_technologies']:
            if providing_technology not in PROVIDING_TECHNOLOGIES:
                errors.append(
                    'ERRORS: Unknown product in providing technologies: %s' %
                    providing_technology)
    # Check to see if datamodel or tstats is in the search.  If so, make sure
    # data_models is defined
    if '| tstats' in search['search'] or 'datamodel' in search['search']:
        if 'data_models' not in search['data_metadata']:
            errors.append(
                "The search uses a data model but 'data_models' \
                        field is not set")

        if 'data_models' in search and not \
                search['data_metadata']['data_models']:
            errors.append(
                "The search uses a data model but 'data_models' is empty")

    if 'sourcetype' in search['search']:
        if 'data_sourcetypes' not in search['data_metadata']:
            errors.append(
                "The search specifies a sourcetype but 'data_sourcetypes' \
                        field is not set")

        if 'data_sourcetypes' in search and not \
                search['data_metadata']['data_sourcetypes']:
            errors.append(
                "The search specifies a sourcetype but \
                        'data_sourcetypes' is empty")

    try:
        search['search_description'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("search_description not ascii")

    if 'how_to_implement' in search:
        try:
            search['how_to_implement'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("how_to_implement not ascii")

    if 'eli5' in search:
        try:
            search['eli5'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("eli5 not ascii")

    if 'known_false_positives' in search:
        try:
            search['known_false_positives'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("known_false_positives not ascii")

    if 'correlation_rule' in search and 'notable' in \
            search['correlation_rule']:
        try:
            search['correlation_rule']['notable']['rule_title'].encode('ascii')
        except UnicodeEncodeError:
            errors.append("rule_title not ascii")

        try:
            search['correlation_rule']['notable']['rule_description'].encode(
                'ascii')
        except UnicodeEncodeError:
            errors.append("rule_description not ascii")

    return errors


def validate_story_manifest(story):
    ''' Validate that the analytic story manifest is in the proper format '''
    errors = []

    if story['id'] == '':
        errors.append('ERROR: Blank Content ID')

    if story['id'] in ALL_UUIDS:
        errors.append('ERROR: Duplicate UUID found: %s' % story['id'])
    else:
        ALL_UUIDS.append(story['id'])

    try:
        story['description'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("description not ascii")

    try:
        story['narrative'].encode('ascii')
    except UnicodeEncodeError:
        errors.append("narrative not ascii")

    if story['category'] not in STORY_CATEGORIES:
        errors.append('ERROR: Invalid category found: %s' % story['category'])
    return errors


def main():
    ''' Open manifest file, validate required fields '''

    errors = False
    story_manifests = {}
    story_schema_file = path.join(
        path.expanduser(MANIFEST_DIRECTORY),
        'spec/analytic_story.json.spec')
    story_schema = json.loads(open(story_schema_file, 'rb').read())
    story_manifest_files = path.join(path.expanduser(MANIFEST_DIRECTORY),
                                     "*/stories/*.json")
    for story_manifest_file in glob.glob(story_manifest_files):
        try:
            story_manifest_data = json.loads(
                open(story_manifest_file, 'r').read())
        except Exception as e:
            print "Error reading %s" % story_manifest_file
            errors = True
            continue

        try:
            jsonschema.validate(story_manifest_data, story_schema)
        except jsonschema.exceptions.ValidationError as json_ve:
            print story_manifest_file
            print json_ve.message
            errors = True
            continue

        story_errors = validate_story_manifest(story_manifest_data)
        if story_errors:
            errors = True
            for err in story_errors:
                print path.basename(story_manifest_file)
                print "\t%s" % err

        story_manifests[story_manifest_data['name']] = story_manifest_data

    detection_search_schema_file = path.join(
        path.expanduser(MANIFEST_DIRECTORY), 'spec/detection_search.json.spec')
    detection_search_schema = json.loads(
        open(detection_search_schema_file, 'rb').read())
    contextual_search_schema_file = path.join(
        path.expanduser(MANIFEST_DIRECTORY),
        'spec/contextual_search.json.spec')
    contextual_search_schema = json.loads(
        open(contextual_search_schema_file, 'rb').read())
    investigative_search_schema_file = path.join(
        path.expanduser(MANIFEST_DIRECTORY),
        'spec/investigative_search.json.spec')
    investigative_search_schema = json.loads(
        open(investigative_search_schema_file, 'rb').read())
    support_search_schema_file = path.join(
        path.expanduser(MANIFEST_DIRECTORY), 'spec/support_search.json.spec')
    support_search_schema = json.loads(
        open(support_search_schema_file, 'rb').read())

    search_manifests = {}
    search_manifest_files = path.join(
        path.expanduser(MANIFEST_DIRECTORY), "*/searches/*.json")
    for search_manifest_file in glob.glob(search_manifest_files):
        try:
            search_manifest_data = json.loads(
                open(search_manifest_file, 'r').read())
        except Exception as e:
            errors = True
            print "Error reading %s" % search_manifest_file
            print e
            continue

        if 'status' in search_manifest_data and \
                search_manifest_data['status'] == 'development':
            continue

        if 'search_type' not in search_manifest_data:
            print "Error in %s, no search_type found" % search_manifest_file
            errors = True
            continue

        if search_manifest_data['search_type'] not in [
                'support', 'detection', 'contextual', 'investigative']:
            print "Error in %s, invalid search_type, %s, found" % (
                search_manifest_file, search_manifest_data)
            errors = True
            continue

        try:
            if search_manifest_data['search_type'] == 'detection':
                search_schema = detection_search_schema
            elif search_manifest_data['search_type'] == 'contextual':
                search_schema = contextual_search_schema
            elif search_manifest_data['search_type'] == 'investigative':
                search_schema = investigative_search_schema
            else:
                search_schema = support_search_schema

            jsonschema.validate(search_manifest_data, search_schema)
        except jsonschema.exceptions.ValidationError as json_ve:
            errors = True
            print search_manifest_file
            print json_ve.message
        except Exception as broad_exception:
            errors = True
            print search_manifest_file
            print broad_exception

        sm_errors = validate_search_manifest(search_manifest_data)
        if sm_errors:
            errors = True
            for err in sm_errors:
                print path.basename(search_manifest_file)
                print "\t%s" % err

        search_manifests[search_manifest_data['search_name']
                         ] = search_manifest_data

    for story_name, story_data in story_manifests.iteritems():
        if 'detection_searches' in story_data['searches']:
            for ds in story_data['searches']['detection_searches']:
                if ds not in search_manifests:
                    print "INFO: %s has a detection search, \
                        %s, not in local repo. Verify name of search provided \
                        in Enterprise Security Content Updates" % (
                        story_name, ds)
                    continue

                if search_manifests[ds]['search_type'] != 'detection':
                    errors = True
                    print "ERROR: \"%s\" mislabeled \"%s\" \
                        as a detection search" % (
                        story_name, ds)

        if 'investigative_searches' in story_data['searches']:
            for invs in story_data['searches']['investigative_searches']:
                if invs not in search_manifests:
                    print "INFO: %s has an investigative search, \
                    %s, not in local repo. \
                    Verify name of search provided in \
                    Enterprise Security Content Updates" % (
                        story_name, invs)
                    continue

                if search_manifests[invs]['search_type'] != 'investigative':
                    errors = True
                    print "ERROR: \"%s\" mislabeled \"%s\" \
                            as a investigative search" % (
                        story_name, invs)

        if 'contextual_searches' in story_data['searches']:
            for cs in story_data['searches']['contextual_searches']:
                if cs not in search_manifests:
                    print "INFO: %s has a contextual search, \
                        %s, not in local repo. Verify name of search provided \
                        in Enterprise Security Content Updates" \
                        % (story_name, cs)
                    continue

                if search_manifests[cs]['search_type'] != 'contextual':
                    errors = True
                    print "ERROR: \"%s\" mislabeled \"%s\" \
                           as a contextual search" % (
                        story_name, cs)

        if 'support_searches' in story_data['searches']:
            for ss in story_data['searches']['support_searches']:
                if ss not in search_manifests:
                    print "INFO: %s has a support search, %s, \
                    not in local repo. Verify name of search provided \
                    in Enterprise Security Content Updates" % (
                        story_name, ss)
                    continue

                if search_manifests[ss]['search_type'] != 'support':
                    errors = True
                    print "ERROR: \"%s\" mislabeled \"%s\" \
                        as a support search" % (
                        story_name, ss)

    print "%d story manifests checked" % len(story_manifests)
    print "%d search manifests checked" % len(search_manifests)

    if errors:
        sys.exit("Errors found")
    else:
        print "No errors found"


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="validates security content manifests", epilog="""
        Validates security manifest for correctness, adhering to spec and other common items.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-security content repo")

    # parse them
    args = parser.parse_args()
    MANIFEST_DIRECTORY = args.path
    main()
