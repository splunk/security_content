import os


from contentctl_core.application.adapter.adapter import Adapter
from contentctl_core.domain.entities.enums.enums import SecurityContentType
from contentctl_infrastructure.adapter.md_writer import MdWriter


class ObjToMdAdapter(Adapter):

    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:

        attack_tactics = set()
        datamodels = set()
        categories = set()
        for story in objects[0]:
            if story.tags.category:
                categories.update(story.tags.category)

        for detection in objects[1]:
            for attack in detection.tags.mitre_attack_enrichments:
                attack_tactics.update(attack.mitre_attack_tactics)

            if detection.datamodel:
                datamodels.update(detection.datamodel)

        MdWriter.writeObjectsList('doc_navigation.j2', os.path.join(output_path, '_data/navigation.yml'),
            {
                'attack_tactics': sorted(list(attack_tactics)), 
                'datamodels': sorted(list(datamodels)), 
                'categories': sorted(list(categories))
            }
        )

        self.writeNavigationPageObjects(sorted(list(datamodels)), output_path)
        self.writeNavigationPageObjects(sorted(list(attack_tactics)), output_path)
        self.writeNavigationPageObjects(sorted(list(categories)), output_path)

        MdWriter.writeObjectsList('doc_story_page.j2', os.path.join(output_path, '_pages/stories.md'), objects[0])
        self.writeObjectsMd(objects[0], os.path.join(output_path, '_stories'), 'doc_stories.j2')

        MdWriter.writeObjectsList('doc_detection_page.j2', os.path.join(output_path, '_pages/detections.md'), objects[1])
        self.writeObjectsMd(objects[1], os.path.join(output_path, '_posts'), 'doc_detections.j2')

        MdWriter.writeObjectsList('doc_playbooks_page.j2', os.path.join(output_path, '_pages/paybooks.md'), objects[2])
        self.writeObjectsMd(objects[2], os.path.join(output_path, '_playbooks'), 'doc_playbooks.j2')


    def writeNavigationPageObjects(self, objects: list, output_path: str) -> None:
        for obj in objects:
            MdWriter.writeObject('doc_navigation_pages.j2', os.path.join(output_path, '_pages', obj.lower().replace(' ', '_') + '.md'),
                {
                    'name': obj
                }
            )

    def writeObjectsMd(self, objects, output_path: str, template_name: str) -> None:
        for obj in objects:
            MdWriter.writeObject(template_name, os.path.join(output_path, obj.name.lower().replace(' ', '_') + '.md'), obj)