import os


from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.adapter.jinja_writer import JinjaWriter


class ObjToMdAdapter(Adapter):

    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:

        attack_tactics = set()
        datamodels = set()
        categories = set()
        for story in objects[0]:
            if story.tags.category:
                categories.update(story.tags.category)

        for detection in objects[1]:
            if detection.tags.mitre_attack_enrichments:
                for attack in detection.tags.mitre_attack_enrichments:
                    attack_tactics.update(attack.mitre_attack_tactics)

            if detection.datamodel:
                datamodels.update(detection.datamodel)

        JinjaWriter.writeObjectsList('doc_navigation.j2', os.path.join(output_path, '_data/navigation.yml'),
            {
                'attack_tactics': sorted(list(attack_tactics)), 
                'datamodels': sorted(list(datamodels)), 
                'categories': sorted(list(categories))
            }
        )

        self.writeNavigationPageObjects(sorted(list(datamodels)), output_path)
        self.writeNavigationPageObjects(sorted(list(attack_tactics)), output_path)
        self.writeNavigationPageObjects(sorted(list(categories)), output_path)

        JinjaWriter.writeObjectsList('doc_story_page.j2', os.path.join(output_path, '_pages/stories.md'), sorted(objects[0], key=lambda x: x.name))
        self.writeObjectsMd(objects[0], os.path.join(output_path, '_stories'), 'doc_stories.j2')

        JinjaWriter.writeObjectsList('doc_detection_page.j2', os.path.join(output_path, '_pages/detections.md'), sorted(objects[1], key=lambda x: x.name))
        self.writeDetectionsMd(objects[1], os.path.join(output_path, '_posts'), 'doc_detections.j2')

        JinjaWriter.writeObjectsList('doc_playbooks_page.j2', os.path.join(output_path, '_pages/paybooks.md'), sorted(objects[2], key=lambda x: x.name))
        self.writeObjectsMd(objects[2], os.path.join(output_path, '_playbooks'), 'doc_playbooks.j2')


    def writeNavigationPageObjects(self, objects: list, output_path: str) -> None:
        for obj in objects:
            JinjaWriter.writeObject('doc_navigation_pages.j2', os.path.join(output_path, '_pages', obj.lower().replace(' ', '_') + '.md'),
                {
                    'name': obj
                }
            )

    def writeObjectsMd(self, objects, output_path: str, template_name: str) -> None:
        for obj in objects:
            JinjaWriter.writeObject(template_name, os.path.join(output_path, obj.name.lower().replace(' ', '_') + '.md'), obj)

    def writeDetectionsMd(self, objects, output_path: str, template_name: str) -> None:
        for obj in objects:
            JinjaWriter.writeObject(template_name, os.path.join(output_path, obj.date + '-' + obj.name.lower().replace(' ', '_') + '.md'), obj)