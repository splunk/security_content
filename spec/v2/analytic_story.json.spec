{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "Analytic Story Manifest",
  "description": "The fields that make up the manifest of a version 2 Analytic Story",
  "type": "object",
  "properties": {
    "id": {
      "description": "A unique identifier for the Analytic Story",
      "type": "string"
    },
    "category": {
      "description": "The category to which the Analytic Story belongs",
      "enum": [
        "Abuse",
        "Adversary Tactics",
        "Best Practices",
        "Cloud Security",
        "Malware",
        "Vulnerability"
      ]
    },
    "channel": {
      "description": "A grouping function that designates where this search came from. For example, searches and stories in Enterprise Security Content Updates are in the ESCU channel",
      "type": "string"
    },
    "original_authors": {
      "description": "An array of the original authors of the Analytic Story",
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "company": {
            "type": "string",
            "description": "Company associated with the person who originally authored the Analytic Story"
          },
          "email": {
            "type": "string",
            "description": "Email address of the person who originally authored the Analytic Story"
          },
          "name": {
            "type": "string",
            "description": "Name of the person who originally authored the Analytic Story"
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
            "description": "Company associated with the person maintaining this Analytic Story"
          },
          "email": {
            "type": "string",
            "description": "Email address of the person maintaining this Analytic Story"
          },
          "name": {
            "type": "string",
            "description": "Name of the person maintaining this Analytic Story"
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
    "creation_date": {
      "description": "The date this story was created",
      "type": "string"
    },
    "modification_date": {
      "description": "The date of the most recent modification to this Analytic Story",
      "type": "string"
    },
    "name": {
      "description": "The name of the Analytic Story",
      "type": "string"
    },
    "description": {
      "description": "A high-level description or goal of the Analytic Story",
      "type": "string"
    },
    "narrative": {
      "description": "Long-form text that describes the Analytic Story and the rationale behind it, as well as an overview of the included searches, and how they enable the story",
      "type": "string"
    },
    "detections": {
      "description": "An array of detection mechanisms from Splunk, UBA and phantom. ",
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "detection_id": {
            "type": "string",
            "description": "unique identifier of the detection, in the form of UUID"
          },
          "type": {
            "type": "string",
            "description": "What product gives you a detection",
             "enum": ["splunk", "uba", "phantom"]
          },
          "name": {
            "type": "string",
            "description": "Name of the Detection. It can be a name of a Splunk correlation search name, a UBA threat or a Phantom detection playbook."
          }
        },
        "additionalProperties": false,
        "required": [
          "detection_id",
          "type",
          "name"
        ]
      }
    },
    "references": {
      "description": "An array of URLs that give information about the problem the story is addressing",
      "type": "array",
      "items": {
        "type": "string"
      },
      "minItems": 0,
      "uniqueItems": true
    },

    "spec_version": {
      "description": "The version of the Analytic Story specification this manifest follows",
      "type": "integer"
    },
    "version": {
      "description": "The version of the Analytic Story",
      "type": "string"
    }
  },
  "additionalProperties": false,
  "required": [
    "category",
    "channel",
    "creation_date",
    "description",
    "id",
    "maintainers",
    "modification_date",
    "narrative",
    "original_authors",
    "name",
    "references",
    "detections",
    "spec_version",
    "version"
  ]
}