

class NewContentQuestions():

    @classmethod
    def get_questions_detection(self) -> list:
        questions = [
            {
                'type': 'list',
                'message': 'what kind of detection is this',
                'name': 'detection_kind',
                'choices': [
                    {
                        'name': 'endpoint'
                    },
                    {
                        'name': 'cloud'
                    },
                    {
                        'name': 'application'
                    },
                    {
                        'name': 'network'
                    },
                    {
                        'name': 'web'
                    },
                    {
                        'name': 'experimental'
                    },

                ],
                'default': 'endpoint'
            },
            {
                'type': 'input',
                'message': 'enter detection name',
                'name': 'detection_name',
                'default': 'Powershell Encoded Command',
            },
            {
                'type': 'input',
                'message': 'enter author name',
                'name': 'detection_author',
            },
            {
                'type': 'list',
                'message': 'select a detection type',
                'name': 'detection_type',
                'choices': [
                    {
                        'name': 'TTP'
                    },
                    {
                        'name': 'Anomaly'
                    },
                    {
                        'name': 'Hunting'
                    },
                    {
                        'name': 'Baseline'
                    },
                    {
                        'name': 'Investigation'
                    },
                    {
                        'name': 'Correlation'
                    }

                ],
                'default': 'TTP'
            },
            {
                'type': 'checkbox',
                'message': 'select the datamodels used in the detection',
                'name': 'datamodels',
                'choices': [
                    {
                        'name': 'Endpoint',
                        'checked': True
                    },
                    {
                        'name': 'Authentication'
                    },
                    {
                        'name': 'Change'
                    },
                    {
                        'name': 'Email'
                    },
                    {
                        'name': 'Network_Resolution'
                    },
                    {
                        'name': 'Network_Traffic'
                    },
                    {
                        'name': 'Network_Sessions'
                    },
                    {
                        'name': 'Updates'
                    },
                    {
                        'name': 'Vulnerabilities'
                    },
                    {
                        'name': 'Web'
                    },
                    {
                        'name': 'Risk'
                    },
                ],
            },
            {
                'type': 'input',
                'message': 'enter search (spl)',
                'name': 'detection_search',
                'default': '| UPDATE_SPL'
            },
            {
                'type': 'input',
                'message': 'enter MITRE ATT&CK Technique IDs related to the detection, comma delimited for multiple',
                'name': 'mitre_attack_ids',
                'default': 'T1003.002'
            },
            {
                'type': 'checkbox',
                'message': 'select kill chain phases related to the detection',
                'name': 'kill_chain_phases',
                'choices': [

                    {
                        'name': 'Reconnaissance'
                    },
                    {
                        'name': 'Intrusion'
                    },
                    {
                        'name': 'Exploitation',
                        'checked': True
                    },
                    {
                        'name': 'Privilege Escalation'
                    },
                    {
                        'name': 'Lateral Movement'
                    },
                    {
                        'name': 'Obfuscation'
                    },
                    {
                        'name': 'Denial of Service'
                    },
                    {
                        'name': 'Exfiltration'
                    },
                ],
            },
            {
                'type': 'list',
                'message': 'security_domain for detection',
                'name': 'security_domain',
                'choices': [
                    {
                        'name': 'access'
                    },
                    {
                        'name': 'endpoint'
                    },
                    {
                        'name': 'network'
                    },
                    {
                        'name': 'threat'
                    },
                    {
                        'name': 'identity'
                    },
                    {
                        'name': 'audit'
                    },

                ],
                'default': 'endpoint'
            },
        ]
        return questions


    @classmethod
    def get_questions_story(self) -> list:
        questions = [
            {
                'type': 'input',
                'message': 'enter story name',
                'name': 'story_name',
                'default': 'Suspicious Powershell Behavior',
            },
            {
                'type': 'input',
                'message': 'enter author name',
                'name': 'story_author',
            },
            {
                'type': 'checkbox',
                'message': 'select a category',
                'name': 'category',
                'choices': [
                    {
                        'name': 'Adversary Tactics',
                        'checked': True
                    },
                    {
                        'name': 'Account Compromise'
                    },
                    {
                        'name': 'Unauthorized Software'
                    },
                    {
                        'name': 'Best Practices'
                    },
                    {
                        'name': 'Cloud Security'
                    },
                    {
                        'name': 'Command and Control'
                    },
                    {
                        'name': 'Lateral Movement'
                    },
                    {
                        'name': 'Ransomware'
                    },
                    {
                        'name': 'Privilege Escalation'
                    },
                    ],
                },
                {
                    'type': 'list',
                    'message': 'select a use case',
                    'name': 'usecase',
                    'choices': [
                        {
                            'name': 'Advanced Threat Detection',
                            'checked': True
                        },
                        {
                            'name': 'Security Monitoring'
                        },
                        {
                            'name': 'Compliance'
                        },
                        {
                            'name': 'Insider Threat'
                        },
                        {
                            'name': 'Application Security'
                        },
                        {
                            'name': 'Other'
                        },
                ],
            },
        ]
        return questions