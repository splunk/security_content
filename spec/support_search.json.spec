{
    "$schema": "http://json-schema.org/draft-04/schema#",
    "title": "Support Search Manifest",
    "description": "The fields that make up the manifest of a version 1 support search",
    "type": "object",
    "properties": {
        "channel": {
            "description": "A grouping function that designates where this search came from. For example, searches and stories in Enterprise Security Updates are in the ESCU channel",
            "type": "string"
        },
        "creation_date": {
            "description": "The date the story manifest was created",
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
                        "enum": ["Apache", "AWS", "Bro", "Microsoft Windows", "Linux", "macOS", "Netbackup", "Splunk Enterprise", "Splunk Enterprise Security", "Splunk Stream", "Active Directory", "Bluecoat", "Carbon Black Response", "Carbon Black Protect", "CrowdStrike Falcon", "Microsoft Exchange", "Nessus", "Palo Alto Firewall", "Qualys" , "Sysmon", "Tanium", "Ziften"]
                    },
                    "minItems": 0,
                    "uniqueItems": true
                }
            },
            "additionalProperties": false,
            "required": ["data_source", "providing_technologies"]
        },
        "eli5": {
            "description": "Explain it like I’m 5 - A detail description of the SPL of the search, written in a style that can be understood by a future Splunk expert",
            "type": "string"
        },
        "how_to_implement": {
            "description": "A discussion on how to implement this search, from what needs to be ingested, config files modified, and suggested per site modifications",
            "type": "string"
        },
        "maintainers": {
            "description": "An array of the current maintainers of the Analytic Story.",
            "type": "array",
            "items" :{
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
                "required": ["name", "email", "company"]
            }
        },
        "modification_date": {
            "description": "The date of the most recent modification to the search",
            "type": "string"
        },
        "original_authors": {
            "description": "A list of the original authors of the search",
            "type": "array",
            "items" :{
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
                "required": ["name", "email", "company"]
            }
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
                    "description": "The latest time the search should run against in Splunk format",
                    "type": "string"
                }
            },
            "additionalProperties": false
        },
        "search": {
            "description": "The search (in SPL) executed within core Splunk",
            "type": "string"
        },
        "search_description": {
            "description": "A description of what the search is designed to detect",
            "type": "string"
        },
        "search_id": {
            "description": "The unique identifier for the search",
            "type": "string"
        },
        "search_name": {
            "description": "The name of the search",
            "type": "string"
        },
        "search_type": {
            "description": "The type of the search",
            "enum": ["detection", "investigative", "contextual", "support"]
        },
        "spec_version": {
            "description": "The version of the detection search specification this manifest follows",
            "type": "integer"
        },
        "status": {
            "description": "The current status of the search - development, experimental, production",
            "enum": ["development", "experimental", "production"]
        },
        "team_notes": {
            "description": "Notes for the team about the search",
            "type": "string"
        },
        "version": {
            "description": "The version of the search",
            "type": "string"
        }
    },
    "additionalProperties": false,
    "required": [
        "channel",
        "creation_date",
        "data_metadata",
        "eli5",
        "how_to_implement",
        "maintainers",
        "modification_date",
        "original_authors",
        "scheduling",
        "search",
        "search_description",
        "search_id",
        "search_type",
        "spec_version",
        "version"
    ]
}