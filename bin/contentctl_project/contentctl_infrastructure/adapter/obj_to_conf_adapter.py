import os
import glob
import shutil

from contentctl_core.application.adapter.adapter import Adapter
from contentctl_infrastructure.adapter.conf_writer import ConfWriter


class ObjToConfAdapter(Adapter):

    def writeHeaders(self, output_folder: str) -> None:
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/analyticstories.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/savedsearches.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/collections.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/es_investigations.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/macros.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/transforms.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/workflow_actions.conf'))


    def writeDetections(self, detections: list, output_folder: str) -> None:
        ConfWriter.writeConfFile('savedsearches_detections.j2', 
            os.path.join(output_folder, 'default/savedsearches.conf'), 
            detections)

        ConfWriter.writeConfFile('analyticstories_detections.j2',
            os.path.join(output_folder, 'default/analyticstories.conf'), 
            detections)

        ConfWriter.writeConfFile('macros_detections.j2',
            os.path.join(output_folder, 'default/macros.conf'), 
            detections)


    def writeStories(self, stories: list, output_folder: str) -> None:
        ConfWriter.writeConfFile('analyticstories_stories.j2',
            os.path.join(output_folder, 'default/analyticstories.conf'), 
            stories)


    def writeBaselines(self, baselines: list, output_folder: str) -> None:
        ConfWriter.writeConfFile('savedsearches_baselines.j2', 
            os.path.join(output_folder, 'default/savedsearches.conf'), 
            baselines)


    def writeInvestigations(self, investigations: list, output_folder: str) -> None:
        ConfWriter.writeConfFile('savedsearches_investigations.j2', 
            os.path.join(output_folder, 'default/savedsearches.conf'), 
            investigations)

        workbench_panels = []
        for investigation in investigations:
            if investigation.inputs:
                response_file_name_xml = investigation.lowercase_name + "___response_task.xml"
                workbench_panels.append(investigation)
                investigation.search = investigation.search.replace(">","&gt;")
                investigation.search = investigation.search.replace("<","&lt;")
                ConfWriter.writeConfFileHeader(os.path.join(output_folder, 
                    'default/data/ui/panels/', str("workbench_panel_" + response_file_name_xml)))
                ConfWriter.writeConfFile('panel.j2', 
                    os.path.join(output_folder, 
                    'default/data/ui/panels/', str("workbench_panel_" + response_file_name_xml)),
                    [investigation.search])

        ConfWriter.writeConfFile('es_investigations_investigations.j2', 
            os.path.join(output_folder, 'default/es_investigations.conf'), 
            workbench_panels)

        ConfWriter.writeConfFile('workflow_actions.j2', 
            os.path.join(output_folder, 'default/workflow_actions.conf'), 
            workbench_panels)


    def writeLookups(self, lookups: list, output_folder: str, security_content_path: str) -> None:
        ConfWriter.writeConfFile('collections.j2', 
            os.path.join(output_folder, 'default/collections.conf'), 
            lookups)

        ConfWriter.writeConfFile('transforms.j2', 
            os.path.join(output_folder, 'default/transforms.conf'), 
            lookups)

        files = glob.iglob(os.path.join(security_content_path, 'lookups', '*.csv'))
        for file in files:
            if os.path.isfile(file):
                shutil.copy(file, os.path.join(output_folder, 'lookups'))


    def writeMacros(self, macros: list, output_folder: str) -> None:
        ConfWriter.writeConfFile('macros.j2', 
            os.path.join(output_folder, 'default/macros.conf'), 
            macros)


    def writeObjectsInPlace(self, objects: list) -> None:
        pass


    def writeObjects(self, objects: list, output_path: str) -> None:
        pass