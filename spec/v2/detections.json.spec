{
  "description": "A object that defines the parameters for detecting things using various Splunk capabilities",
  "type": "object",
  "$id": "https://api.splunkresearch.com/schemas/detections.json",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Detection Manifest",
  "properties": {
    "name": {
      "description": "The name of the detection",
      "type": "string"
    },
    "id": {
      "description": "The unique identifier for the detection",
      "type": "string"
    },
    "product_type": {
      "description": "The type of detection",
      "enum": [
        "uba",
        "splunk",
        "phantom"
      ]
    },

    "description": {
      "description": "A description of what the detection is designed to find",
      "type": "string"
    },
    "data_metadata": {
      "type": "object",
      "description": "Information about the date being ingested",
      "properties": {
        "data_models": {
          "description": "A list of data models, if any, used by this search",
          "type": "array",
          "items": {
            "enum": [
              "Alerts",
              "Application_State",
              "Authentication",
              "Certificates",
              "Change_Analysis",
              "Change",
              "Malware",
              "Email",
              "Identity_Management",
              "Network_Resolution",
              "Network_Traffic",
              "Vulnerabilities",
              "Web",
              "Network_Sessions",
              "Updates",
              "Risk",
              "Endpoint"
            ]
          },
          "minItems": 0,
          "uniqueItems": true
        },
        "data_eventtypes": {
          "description": "A list of eventtypes, if any, used by this search",
          "type": "array",
          "items": {
            "type": "string"
          },
          "minItems": 0,
          "uniqueItems": true
        },
        "data_source": {
          "description": "A high-level description of the type of data needed for this search to complete",
          "type": "array",
          "items": {
            "type": "string"
          },
          "minItems": 0,
          "uniqueItems": true
        },
        "data_sourcetypes": {
          "description": "The list of sourcetypes, if any, used by this search",
          "type": "array",
          "items": {
            "type": "string"
          },
          "minItems": 0,
          "uniqueItems": true
        },
        "providing_technologies": {
          "description": "A list of technologies that provide this data",
          "type": "array",
          "items": {
            "enum": [
              "Apache",
              "AWS",
              "Bro",
              "Microsoft Windows",
              "Linux",
              "macOS",
              "Netbackup",
              "Splunk Enterprise",
              "Splunk Enterprise Security",
              "Splunk Stream",
              "Active Directory",
              "Bluecoat",
              "Carbon Black Response",
              "Carbon Black Protect",
              "CrowdStrike Falcon",
              "Microsoft Exchange",
              "Nessus",
              "Palo Alto Firewall",
              "Qualys",
              "Sysmon",
              "Tanium",
              "Ziften",
              "OSquery"
            ]
          },
          "minItems": 0,
          "uniqueItems": true
        }
      },
      "additionalProperties": false,
      "required": [
        "data_source",
        "providing_technologies"
      ]
    },
    "creation_date": {
      "description": "The date the story manifest was created",
      "type": "string"
    },
    "mappings": {
      "type": "object",
      "description": "Mappings to various industry standards and frameworks",
      "properties": {
        "cis20": {
          "description": "A list of critical security controls this search helps you implement",
          "type": "array",
          "items": {
            "enum": [
              "CIS 1",
              "CIS 2",
              "CIS 3",
              "CIS 4",
              "CIS 5",
              "CIS 6",
              "CIS 7",
              "CIS 8",
              "CIS 9",
              "CIS 10",
              "CIS 11",
              "CIS 12",
              "CIS 13",
              "CIS 14",
              "CIS 15",
              "CIS 16",
              "CIS 17",
              "CIS 18",
              "CIS 19",
              "CIS 20"
            ]
          },
          "minItems": 0,
          "uniqueItems": true
        },
        "kill_chain_phases": {
          "description": "A list of kill-chain phases to which the search applies",
          "type": "array",
          "items": {
            "enum": [
              "Reconnaissance",
              "Weaponization",
              "Delivery",
              "Exploitation",
              "Installation",
              "Command and Control",
              "Actions on Objectives"
            ]
          },
          "minItems": 0,
          "uniqueItems": true
        },
        "mitre_attack": {
          "description": "A list of the techniques and tactics identified by the search",
          "type": "array",
          "items": {
            "enum": [
              "Initial Access",
              "Execution",
              "Persistence",
              "Privilege Escalation",
              "Defense Evasion",
              "Credential Access",
              "Discovery",
              "Lateral Movement",
              "Collection",
              "Exfiltration",
              "Command and Control",
              "Command and Control Protocol",
              "Commonly Used Port",
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
              "Exploitation for Privilege Escalation"
            ]
          },
          "minItems": 0,
          "uniqueItems": true
        },
        "nist": {
          "description": "A list of the NIST controls the search helps you implement",
          "type": "array",
          "items": {
            "enum": [
              "ID.AM",
              "ID.RA",
              "PR.DS",
              "PR.IP",
              "PR.AC",
              "PR.PT",
              "PR.AT",
              "PR.MA",
              "DE.CM",
              "DE.DP",
              "DE.AE",
              "RS.MI",
              "RS.AN",
              "RS.RP",
              "RS.IM",
              "RS.CO",
              "RC.IM",
              "RC.CO"
            ]
          },
          "minItems": 0,
          "uniqueItems": true
        },
        "emoji": {
          "description": "A list of security emojis that will help UBA understand this alert as an external alarm",
          "type": "array",
          "items": {
            "enum": [
              "EndPoint",
              "AD",
              "Firewall",
              "ApplicationLog",
              "IPS",
              "CloudData",
              "Correlation",
              "Printer",
              "Badge"
            ]
          },
          "minItems": 0,
          "uniqueItems": true
        }
      },
      "additionalProperties": false
    },
    "how_to_implement": {
      "description": "A discussion on how to implement this search, from what needs to be ingested, config files modified, and suggested per site modifications",
      "type": "string"
    },
    "eli5": {
      "description": "Explain it like I’m 5 - A detail description of the SPL of the search, written in a style that can be understood by a future Splunk expert",
      "type": "string"
    },
    "confidence": {
      "description": "Confidence that detected behavior is malicious",
      "enum": [
        "high",
        "medium",
        "low"
      ]
    },
    "asset_type": {
      "description": "Designates the type of asset being investigated",
      "type": "string"
    },
    "entities": {
      "description": "A list of entities that is outputed by the search...",
      "type": "array",
      "items": {

        "enum": [
                 "accessKeyId",
                  "arn",
                  "awsRegion",
                  "bucketName",
                  "City",
                  "Country",
                  "dest_port",
                  "dest",
                  "event_id",
                  "instanceId",
                  "message_id",
                  "networkAclId",
                  "process_name",
                  "process",
                  "recipient",
                  "Region",
                  "resourceId",
                  "session_id",
                  "src_ip",
                  "src_ip",
                  "src_mac",
                  "src_user",
                  "src",
                  "user"
                  ]
      },
      "minItems": 0,
      "uniqueItems": true
    },
    "known_false_positives": {
      "description": "Scenarios in which detected behavior is benig, coupled with suggestions on how to verify the behavior",
      "type": "string"
    },
    "maintainers": {
      "description": "An array of the current maintainers of the Analytic Story.",
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "company": {
            "type": "string",
            "description": "Company associated with the person maintaining this search"
          },
          "email": {
            "type": "string",
            "description": "Email address of the person maintaining this search"
          },
          "name": {
            "type": "string",
            "description": "Name of the person maintaining this search"
          }
        },
        "additionalProperties": false,
        "required": [
          "name",
          "email",
          "company"
        ]
      }
    },
    "baselines": {
      "description": "An array of the baseline objects to exectute before the detection ",
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "type": {
            "product_type": "string",
            "description": "Type of baseline to execute",
            "enum": [
              "phantom",
              "splunk",
              "uba"
            ]
          },
          "name": {
            "type": "string",
            "description": "name of baseline object"
          },
          "id": {
            "type": "string",
            "description": "UUID of the baseline object"
          }
        },
        "additionalProperties": false,
        "required": [
          "product_type",
          "name",
          "id"
        ]
      }
    },
    "investigations": {
      "description": "An array of the investigation objects to exectute on the detection results ",
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "product_type": {
            "type": "string",
            "description": "Type of baseline to execute",
            "enum": [
              "phantom",
              "splunk",
              "uba"
            ]
          },
          "name": {
            "type": "string",
            "description": "Name of baseline"
          },
          "id": {
            "type": "string",
            "description": "UUID of the baseline object"
          }
        },
        "additionalProperties": false,
        "required": [
          "product_type",
          "name",
          "id"
        ]
      }
    },
    "responses": {
      "description": "An array of the response objects to exectute on the detection results ",
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "product_type": {
            "product_type": "string",
            "description": " Product that will execute the response",
            "enum": [
              "phantom",
              "splunk",
              "uba"
            ]
          },
          "name": {
            "type": "string",
            "description": "Name of baseline object"
          },
          "id": {
            "type": "string",
            "description": "UUID of the baseline object"
          }
        },
        "additionalProperties": false,
        "required": [
          "product_type",
          "name",
          "id"
        ]
      }
    },
    "modification_date": {
      "description": "The date of the most recent modification to the search",
      "type": "string"
    },
    "original_authors": {
      "description": "A list of the original authors of the search",
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "company": {
            "type": "string",
            "description": "Company associated with the person who originally authored the search"
          },
          "email": {
            "type": "string",
            "description": "Email address of the person who originally authored the search"
          },
          "name": {
            "type": "string",
            "description": "Name of the person who originally authored the search"
          }
        },
        "additionalProperties": false,
        "required": [
          "name",
          "email",
          "company"
        ]
      }
    },
    "references": {
      "description": "A list of URLs that give more information about the search",
      "type": "array",
      "items": {
        "type": "string"
      },
      "minItems": 0,
      "uniqueItems": true
    },
    "security_domain": {
      "description": "The high-level security area to which the search belongs",
      "enum": [
        "access",
        "endpoint",
        "network",
        "threat"
      ]
    },
    "spec_version": {
      "description": "The version of the detection specification this manifest follows",
      "type": "integer"
    },
    "version": {
      "description": "The version of the detection",
      "type": "string"
    },
    "detect": {
      "oneOf": [
        {
          "$ref": "#/definitions/splunk"
        },
        {
          "$ref": "#/definitions/phantom"
        },
        {
          "$ref": "#/definitions/uba"
        }
      ]
    }
  },
  "additionalProperties": false,
  "definitions": {
    "splunk": {
      "type": "object",
      "properties": {
        "correlation_rule": {
          "type": "object",
          "description": "Various fields to enhance usability in Enterprise Security",
          "properties": {
            "notable": {
              "type": "object",
              "description": "Various fields associated with creating a notable event",
              "properties": {
                "rule_description": {
                  "description": "Description of the notable event that will display in Incident Review",
                  "type": "string"
                },
                "rule_title": {
                  "description": "Title of the notable event that will display in Incident Review",
                  "type": "string"
                },
                "nes_fields": {
                  "description": "A list of suggested fields to be used for notable-event suppression",
                  "type": "string"
                }
              },
              "additionalProperties": false,
              "required": [
                "rule_description",
                "rule_title",
                "nes_fields"
              ]
            },
            "risk": {
              "type": "object",
              "description": "Fields associated with assigning risk to objects",
              "properties": {
                "risk_object": {
                  "description": "TThe field to which you are assigning risk",
                  "type": "string"
                },
                "risk_object_type": {
                  "description": "The type of object to which you’re assigning risk",
                  "type": "array",
                  "items": {
                    "type": "string",
                    "enum": [
                      "system",
                      "user",
                      "other"
                    ]
                  },
                  "minItems": 0,
                  "maxItems": 1,
                  "uniqueItems": true
                },
                "risk_score": {
                  "description": "Score assigned to risk_object",
                  "type": "integer"
                }
              },
              "additionalProperties": false,
              "required": [
                "risk_score",
                "risk_object",
                "risk_object_type"
              ]
            },
            "suppress": {
              "type": "object",
              "description": "Fields associated with suppressing the creation of multiple alerts",
              "properties": {
                "suppress_fields": {
                  "description": "The fields to base the suppression on",
                  "type": "string"
                },
                "suppress_period": {
                  "description": "The length of time the suppression should be in effect",
                  "type": "string"
                }
              },
              "additionalProperties": false,
              "required": [
                "suppress_fields",
                "suppress_period"
              ]
            }
          },
          "additionalProperties": false
        },
        "scheduling": {
          "type": "object",
          "description": "Various fields to assist in scheduling the search",
          "properties": {
            "cron_schedule": {
              "description": "Schedule of the search in cron format",
              "type": "string"
            },
            "earliest_time": {
              "description": "The earliest time the search should run in Splunk format",
              "type": "string"
            },
            "latest_time": {
              "description": "The latest time tes search should run against in Splunk format",
              "type": "string"
            }
          },
          "additionalProperties": false
        },
        "search": {
          "description": "The search (in SPL) executed within Splunk",
          "type": "string"
        }
      }
    },
    "phantom": {
      "type": "object",
      "properties": {
        "phantom_server": {
          "type": "string",
          "description": "IP address and username of the phantom server. Currently, we will ship this value as automation (hostname) and we encourage the users to modify those values according to their environment. Eg: automation (hostname)"
        },
        "playbook_name": {
          "type": "string",
          "description": "Name of the playbook. This name should be the same as the name on phantom community repository on github with underscores and appended with community/<playbook_name>. The playbooks are hosted on https://github.com/phantomcyber/playbooks. Eg: community/simple_network_enrichment"
        },
        "playbook_display_name": {
          "type": "string",
          "description": "Display Name of the playbook. Capitalize each letter and remove underscores from playbook_name field. Eg: Simple Network Enrichment"
        },
        "playbook_url": {
          "type": "string",
          "description": "Url of the playbook on Phantom website."
        },
        "sensitivity": {
          "type": "string",
          "description": "TLP colors (White, Green, Amber or Red)"
        },
        "severity": {
          "type": "string",
          "description": "Severity in phantom (High, Medium, Low)"
        }
      },
      "required": [
          "phantom_server",
          "playbook_name",
          "playbook_url",
          "playbook_display_name"
        ]
    },
    "uba": {
      "type": "object",
      "properties": {
        "threat_category": {
          "type": "string",
          "description": "The category of a threat in Splunk UBA."
        },
        "search": {
          "type": "string",
          "description": "The search you will run against the UEBA index to idenfiy the threat."
        },
        "event_type": {
          "type": "string",
          "description": "An anomaly or threat."
        },
        "model": {
          "type": "string",
          "description": "The name of the Splunk UBA model that detected the anomaly."
        },
        "model_version": {
          "type": "string",
          "description": "Url of the playbook on Phantom website."
        }
      }
    }
  },
  "required": [
    "confidence",
    "creation_date",
    "data_metadata",
    "eli5",
    "how_to_implement",
    "known_false_positives",
    "maintainers",
    "modification_date",
    "original_authors",
    "description",
    "id",
    "product_type",
    "security_domain",
    "version",
    "detect"
  ]
}