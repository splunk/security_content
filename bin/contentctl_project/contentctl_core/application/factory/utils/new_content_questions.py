

class NewContentQuestions():

    @classmethod
    def get_questions_detection(self) -> list:
        questions = [
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