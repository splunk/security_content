
import json


VERSION = "4.3"
NAME = "Detection Coverage"
DESCRIPTION = "security_content detection coverage"
DOMAIN = "mitre-enterprise"


class AttackNavWriter():

    @staticmethod
    def writeAttackNavFile(mitre_techniques : dict, output_path : str) -> None:
        max_count = 0
        for technique_id in mitre_techniques.keys():
            if mitre_techniques[technique_id]['score'] > max_count:
                max_count = mitre_techniques[technique_id]['score']
        
        layer_json = {
            "version": VERSION,
            "name": NAME,
            "description": DESCRIPTION,
            "domain": DOMAIN,
            "techniques": []
        }

        layer_json["gradient"] = {
            "colors": [
                "#ffffff",
                "#66b1ff",
                "#096ed7"
            ],
            "minValue": 0,
            "maxValue": max_count
        }

        layer_json["filters"] = {
                "platforms":
                    ["Windows",
                    "Linux",
                    "macOS",
                    "AWS",
                    "GCP",
                    "Azure",
                    "Office 365",
                    "SaaS"
                ]
        }

        layer_json["legendItems"] = [
            {
                "label": "NO available detections",
                "color": "#ffffff"
            },
            {
                "label": "Some detections available",
                "color": "#66b1ff"
            }
        ]

        layer_json['showTacticRowBackground'] = True
        layer_json['tacticRowBackground'] = "#dddddd"
        layer_json["sorting"] = 3

        for technique_id in mitre_techniques.keys():
            layer_technique = {
                "techniqueID": technique_id,
                "score": mitre_techniques[technique_id]['score'],
                "comment": "\n\n".join(mitre_techniques[technique_id]['file_paths'])
            }
            layer_json["techniques"].append(layer_technique)

        with open(output_path, 'w') as outfile:
            json.dump(layer_json, outfile, ensure_ascii=False, indent=4)
