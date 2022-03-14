import os


from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.adapter.jinja_writer import JinjaWriter


class ObjToSvgAdapter(Adapter):

    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:
        
        detections_tmp = objects
        detection_without_test = 0    
      
        detections = []
        obj = dict()

        for detection in detections_tmp:
            if not detection.deprecated:
                detections.append(detection)

                if not detection.test and not detection.experimental:
                    detection_without_test = detection_without_test + 1


        obj['count'] = len(detections) 
        obj['coverage'] = (obj['count'] - detection_without_test)/obj['count']
        obj['coverage'] = "{:.0%}".format(obj['coverage'])

        JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'detection_count.svg'), obj)
        JinjaWriter.writeObject('detection_coverage.j2', os.path.join(output_path, 'detection_coverage.svg'), obj)

