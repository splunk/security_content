{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Investigative Search Manifest",
  "$id": "https://api.splunkresearch.com/schemas/investigations.json",
  "description": "The fields that make up the manifest of a version 1 investigative earch",
  "type": "object",
  "properties": {
    "id": {
      "description": "The unique identifier for the search",
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
        "data_eventtypes": {
          "description": "A list of eventtypes, if any, used by this search",
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
    "fields_required": {
      "description": "A list of fields that need to be in the result of the detection search for the search to be successful",
      "type": "array",
      "items": {
        "type": "string"
      },
      "minItems": 0,
      "uniqueItems": true
    },
    "how_to_implement": {
      "description": "A discussion on how to implement this search, from what needs to be ingested, config files modified, and suggested per site modifications",
      "type": "string"
    },
    "creation_date": {
      "description": "The date the story manifest was created",
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
    "search": {
      "description": "The search (in SPL) executed within core Splunk",
      "type": "string"
    },
    "description": {
      "description": "A description of what the search is designed to detect",
      "type": "string"
    },
    "name": {
      "description": "The name of the search",
      "type": "string"
    },
    "type": {
      "description": "The type of the search",
      "enum": [
        "detection",
        "investigative",
        "contextual",
        "baseline"
      ]
    },
    "spec_version": {
      "description": "The version of the investigative search specification this manifest follows",
      "type": "integer"
    },
    "version": {
      "description": "The version of the search",
      "type": "string"
    },
    "investigate": {
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
        "investigate_window": {
          "type": "object",
          "description": "The fields associated on when this search should run relative to the detection event",
          "properties": {
            "earliest_time_offset": {
              "description": "The number of seconds into the past from the event time the search should cover",
              "type": "integer"
            },
            "latest_time_offset": {
              "description": "The number of seconds into the future from the event time the search should cover",
              "type": "integer"
            }
          },
          "additionalProperties": false,
          "required": [
            "latest_time_offset",
            "earliest_time_offset"
          ]
        },
        "search": {
          "description": "The search (in SPL) executed within core Splunk",
          "type": "string"
        }
      }
    }
  },
  "required": [
    "creation_date",
    "data_metadata",
    "fields_required",
    "how_to_implement",
    "maintainers",
    "modification_date",
    "original_authors",
    "search",
    "description",
    "id",
    "type",
    "investigate_window",
    "spec_version",
    "version",
    "investigate"
  ]
}
