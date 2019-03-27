{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "Baseline Manifest",
  "description": "The fields that make up the manifest of a version 2 baseline search",
  "type": "object",
  "properties": {
    "name": {
      "description": "The name of the search that creates the baseline",
      "type": "string"
    },
    "id": {
      "description": "The unique identifier for the search",
      "type": "string"
    },
    "type": {
      "description": "The type of baseline",
      "enum": [
        "splunk",
        "phantom"
      ]
    },
    "description": {
      "description": "A description of what the search is is doing to create a baseline",
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
            "type": "string"
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
              "Ziften"
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
      "description": "The date the baseline manifest was created",
      "type": "string"
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
    "how_to_implement": {
      "description": "A discussion on how to implement this search, from what needs to be ingested, config files modified, and suggested per site modifications",
      "type": "string"
    },
    "known_false_positives": {
      "description": "Describe the known false postives while the analyst builds the baseline.",
      "type": "string"
    },
    "eli5": {
      "description": "Explain it like I’m 5 - A detail description of the SPL of the search, written in a style that can be understood by a future Splunk expert",
      "type": "string"
    },
    "spec_version": {
      "description": "The version of the detection search specification this manifest follows",
      "type": "integer"
    },
    "version": {
      "description": "The version of the search",
      "type": "string"
    },
    "baseline": {
      "oneOf": [
        {
          "$ref": "#/definitions/splunk"
        },
        {
          "$ref": "#/definitions/phantom"
        }
      ]
    }
  },
  "additionalProperties": false,
  "definitions": {
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
      }
    },
    "splunk": {
      "type": "object",
      "properties": {
        "scheduling": {
          "type": "object",
          "description": "Various fields to assist in scheduling the search",
          "properties": {
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
          "description": "The search (in SPL) executed within core Splunk for creating a baseline",
          "type": "string"
        }
      }
    }
  },
  "required": [
    "id",
    "creation_date",
    "data_metadata",
    "eli5",
    "known_false_positives",
    "how_to_implement",
    "maintainers",
    "modification_date",
    "original_authors",
    "name",
    "description",
    "type",
    "spec_version",
    "version",
    "baseline"
  ]
}