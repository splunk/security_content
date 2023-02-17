import os

from bin.contentctl_project.contentctl_infrastructure.adapter.yml_writer import YmlWriter



class YmlOutput():


    def writeDetections(self, objects: list, output_path : str) -> None:
        for obj in objects:
            file_path = obj.file_path
            YmlWriter.writeYmlFile(os.path.join(output_path, file_path), obj.dict(
                include =
                    {
                        "name": True,
                        "id": True,
                        "version": True,
                        "date": True,
                        "author": True,
                        "type": True,
                        "status": True,
                        "description": True,
                        "data_source": True,
                        "search": True,
                        "how_to_implement": True,
                        "known_false_positives": True,
                        "references": True,
                        "tags": 
                            {
                                "analytic_story": True,
                                "asset_type": True,
                                "atomic_guid": True,
                                "confidence": True,
                                "impact": True,
                                "drilldown_search": True,
                                "message": True,
                                "mitre_attack_id": True,
                                "kill_chain_phases:": True,
                                "observable": True,
                                "product": True,
                                "required_fields": True,
                                "risk_score": True,
                                "security_domain": True
                            },
                        "tests": 
                            {
                                '__all__': 
                                    {
                                        "name": True,
                                        "attack_data": {
                                            '__all__': 
                                            {
                                                "data": True,
                                                "source": True,
                                                "sourcetype": True
                                            }
                                        }
                                    }
                            }
                    }
            ))
            