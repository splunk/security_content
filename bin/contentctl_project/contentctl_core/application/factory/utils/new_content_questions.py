

class NewContentQuestions():

    @classmethod
    def get_questions_detection(self) -> list:
        questions = [
            {
                'type': 'select',
                'message': 'what product is this for',
                'name': 'detection_product',
                'choices': [
                    'ESCU',
                    'SSA'
                ],
                'default': 'ESCU'
            },
            {
                'type': 'select',
                'message': 'what kind of detection is this',
                'name': 'detection_kind',
                'choices': [
                    'endpoint',
                    'cloud',
                    'application',
                    'network',
                    'web',
                    'experimental'
                ],
                'default': 'endpoint'
            },
            {
                'type': 'text',
                'message': 'enter detection name',
                'name': 'detection_name',
                'default': 'Powershell Encoded Command',
            },
            {
                'type': 'text',
                'message': 'enter author name',
                'name': 'detection_author',
            },
            {
                'type': 'select',
                'message': 'select a detection type',
                'name': 'detection_type',
                'choices': [
                    'TTP',
                    'Anomaly',
                    'Hunting',
                    'Baseline',
                    'Investigation',
                    'Correlation'
                ],
                'default': 'TTP'
            },
            {
                'type': 'checkbox',
                'message': 'select the datamodels used in the detection',
                'name': 'datamodels',
                'choices': [
                    'Endpoint',
                    'Endpoint_Processes (SSA)',
                    'Endpoint_Registry (SSA)',
                    'Endpoint_Filesystem (SSA)',
                    'Endpoint_ResourceAccess (SSA)',
                    'Endpoint_AccountManagement (SSA)',
                    'Intrusion_Detection (SSA)',
                    'Authentication',
                    'Change',
                    'Email',
                    'Network_Resolution',
                    'Network_Traffic',
                    'Network_Sessions',
                    'Updates',
                    'Vulnerabilities',
                    'Web',
                    'Risk'
                ],
                'default': 'Endpoint'
            },
            {
                'type': 'text',
                'message': 'enter search (spl)',
                'name': 'detection_search',
                'default': '| UPDATE_SPL'
            },
            {
                'type': 'text',
                'message': 'enter MITRE ATT&CK Technique IDs related to the detection, comma delimited for multiple',
                'name': 'mitre_attack_ids',
                'default': 'T1003.002'
            },
            {
                'type': 'checkbox',
                'message': 'select kill chain phases related to the detection',
                'name': 'kill_chain_phases',
                'choices': [
                    'Reconnaissance',
                    'Weaponization',
                    'Delivery',
                    'Exploitation',
                    'Installation',
                    'Command & Control',
                    'Actions on Objectives',
                    'Denial of Service'
                ],
                'default': 'Exploitation'
            },
            {
                'type': 'select',
                'message': 'security_domain for detection',
                'name': 'security_domain',
                'choices': [
                    'access',
                    'endpoint',
                    'network',
                    'threat',
                    'identity',
                    'audit'
                ],
                'default': 'endpoint'
            },
        ]
        return questions


    @classmethod
    def get_questions_story(self) -> list:
        questions = [
            {
                'type': 'text',
                'message': 'enter story name',
                'name': 'story_name',
                'default': 'Suspicious Powershell Behavior',
            },
            {
                'type': 'text',
                'message': 'enter author name',
                'name': 'story_author',
            },
            {
                'type': 'checkbox',
                'message': 'select a category',
                'name': 'category',
                'choices': [
                    'Adversary Tactics',
                    'Account Compromise',
                    'Unauthorized Software',
                    'Best Practices',
                    'Cloud Security',
                    'Command and Control',
                    'Lateral Movement',
                    'Ransomware',
                    'Privilege Escalation'
                ]
                },
                {
                    'type': 'select',
                    'message': 'select a use case',
                    'name': 'usecase',
                    'choices': [
                        'Advanced Threat Detection',
                        'Security Monitoring',
                        'Compliance',
                        'Insider Threat',
                        'Application Security',
                        'Other'
                ],
            },
        ]
        return questions


    @classmethod
    def get_questions_attack_data(self) -> list:
        questions = [
            {
                'type': 'input',
                'message': 'enter the source file path of your attack_dataset (ex. ~/attack_range/attack_data/stext_sysmon/sysmon.log): ',
                'name': 'src_file_path',
            },
            {
                'type': 'input',
                'message': 'enter the dest folder path for your attack_dataset (ex. ~/attack_data/datasets/malware/remcos/remcos_dynwrapx): ',
                'name': 'dest_file_path',
            },
            {
                'type': 'input',
                'message': 'enter author name: ',
                'name': 'author_name',
                'default': 'STRT',
            },
            {
            'type': 'checkbox',
            'message': 'select the data source type',
            'name': 'data_src_category',
            'choices': [
                {
                    'name': 'windows-sysmon.log',
                    'checked': True
                },
                {
                    'name': 'windows-security.log'
                },
                {
                    'name': 'windows-system.log'
                },
                {
                    'name': 'windows-powershell-xml.log'
                },
                {
                    'name': 'stream_http_events.log'
                },
                {
                    'name': 'aws_cloudtrail_events.json'
                },
                {
                    'name': 'o365_events.json'
                },
                {
                    'name': 'o365_exchange_events.json'
                },
                {
                    'name': 'kubernetes_events.json'
                },
                {
                    'name': 'security_hub_finding.json'
                },
                {
                    'name': 'gsuite_gmail_bigquery.json'
                },
                {
                    'name': 'gsuite_drive_json.json'
                },
                {
                    'name': 'github.json'
                },
                {
                    'name': 'kubernetes_nginx.json'
                },
                {
                    'name': 'circleci.json'
                },
                {
                    'name': 'sysmon_linux.log'
                },
                {
                    'name': 'xml-windows-security.log'
                },
                {
                    'name': 'xml-windows-system.log'
                },
                {
                    'name': 'xml-windows-application.log'
                },
                {
                    'name': 'xml-windows-directory-service.log'
                },
                ],
            },
            {
                'type': 'input',
                'message': 'enter references: ',
                'name': 'references',
            },
        ]
        return questions