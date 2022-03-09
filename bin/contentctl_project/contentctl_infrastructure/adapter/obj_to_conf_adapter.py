import os
import glob
import shutil

from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter
from bin.contentctl_project.contentctl_infrastructure.adapter.conf_writer import ConfWriter
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType


class ObjToConfAdapter(Adapter):

    def writeHeaders(self, output_folder: str) -> None:
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/analyticstories.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/savedsearches.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/collections.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/es_investigations.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/macros.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/transforms.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/workflow_actions.conf'))


    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:
        if type == SecurityContentType.detections:
            ConfWriter.writeConfFile('savedsearches_detections.j2', 
            os.path.join(output_path, 'default/savedsearches.conf'), 
            objects)

            ConfWriter.writeConfFile('analyticstories_detections.j2',
                os.path.join(output_path, 'default/analyticstories.conf'), 
                objects)

            ConfWriter.writeConfFile('macros_detections.j2',
                os.path.join(output_path, 'default/macros.conf'), 
                objects)
        
        elif type == SecurityContentType.stories:
            ConfWriter.writeConfFile('analyticstories_stories.j2',
                os.path.join(output_path, 'default/analyticstories.conf'), 
                objects)

        elif type == SecurityContentType.baselines:
            ConfWriter.writeConfFile('savedsearches_baselines.j2', 
                os.path.join(output_path, 'default/savedsearches.conf'), 
                objects)

        elif type == SecurityContentType.investigations:
            ConfWriter.writeConfFile('savedsearches_investigations.j2', 
                os.path.join(output_path, 'default/savedsearches.conf'), 
                objects)
            
            ConfWriter.writeConfFile('analyticstories_investigations.j2', 
                os.path.join(output_path, 'default/analyticstories.conf'), 
                objects)

            workbench_panels = []
            for investigation in objects:
                if investigation.inputs:
                    response_file_name_xml = investigation.lowercase_name + "___response_task.xml"
                    workbench_panels.append(investigation)
                    investigation.search = investigation.search.replace(">","&gt;")
                    investigation.search = investigation.search.replace("<","&lt;")
                    ConfWriter.writeConfFileHeader(os.path.join(output_path, 
                        'default/data/ui/panels/', str("workbench_panel_" + response_file_name_xml)))
                    ConfWriter.writeConfFile('panel.j2', 
                        os.path.join(output_path, 
                        'default/data/ui/panels/', str("workbench_panel_" + response_file_name_xml)),
                        [investigation.search])

            ConfWriter.writeConfFile('es_investigations_investigations.j2', 
                os.path.join(output_path, 'default/es_investigations.conf'), 
                workbench_panels)

            ConfWriter.writeConfFile('workflow_actions.j2', 
                os.path.join(output_path, 'default/workflow_actions.conf'), 
                workbench_panels)   

        elif type == SecurityContentType.lookups:
            ConfWriter.writeConfFile('collections.j2', 
                os.path.join(output_path, 'default/collections.conf'), 
                objects)

            ConfWriter.writeConfFile('transforms.j2', 
                os.path.join(output_path, 'default/transforms.conf'), 
                objects)

            files = glob.iglob(os.path.join(os.path.dirname(__file__), '../../../..' , 'lookups', '*.csv'))
            for file in files:
                if os.path.isfile(file):
                    shutil.copy(file, os.path.join(output_path, 'lookups'))

        elif type == SecurityContentType.macros:
            ConfWriter.writeConfFile('macros.j2', 
                os.path.join(output_path, 'default/macros.conf'), 
                objects)

