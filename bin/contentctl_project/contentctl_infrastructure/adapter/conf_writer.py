import datetime
import os
from jinja2 import Environment, FileSystemLoader

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject

class ConfWriter():

    @staticmethod
    def writeConfFileHeader(output_path : str) -> None:
        utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True)

        template = j2_env.get_template('header.j2')
        output = template.render(time=utc_time)
        with open(output_path, 'w') as f:
            output = output.encode('ascii', 'ignore').decode('ascii')
            f.write(output)


    @staticmethod
    def writeConfFile(template_name : str, output_path : str, objects : list) -> None:

        def custom_jinja2_enrichment_filter(string, object):
            customized_string = string

            for key in dir(object):
                if type(key) is not str:
                    key = key.decode()
                if not key.startswith('__') and not key == "_abc_impl" and not callable(getattr(object, key)):
                    if hasattr(object, key):
                        customized_string = customized_string.replace("%" + key + "%", str(getattr(object, key)))

            for key in dir(object.tags):
                if type(key) is not str:
                    key = key.decode()
                if not key.startswith('__') and not key == "_abc_impl" and not callable(getattr(object.tags, key)):
                    if hasattr(object.tags, key):
                        customized_string = customized_string.replace("%" + key + "%", str(getattr(object.tags, key)))

            return customized_string

        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True)

        j2_env.filters['custom_jinja2_enrichment_filter'] = custom_jinja2_enrichment_filter
        template = j2_env.get_template(template_name)
        output = template.render(objects=objects)
        with open(output_path, 'a') as f:
            output = output.encode('ascii', 'ignore').decode('ascii')
            f.write(output)

