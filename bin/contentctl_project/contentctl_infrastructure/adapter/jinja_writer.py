import os

from jinja2 import Environment, FileSystemLoader


class JinjaWriter:

    @staticmethod
    def writeObjectsList(template_name : str, output_path : str, objects : list) -> None:

        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=False)

        template = j2_env.get_template(template_name)
        output = template.render(objects=objects)
        with open(output_path, 'w') as f:
            output = output.encode('ascii', 'ignore').decode('ascii')
            f.write(output)


    @staticmethod
    def writeObject(template_name : str, output_path : str, object : dict) -> None:

        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=False)

        template = j2_env.get_template(template_name)
        output = template.render(object=object)
        with open(output_path, 'w') as f:
            output = output.encode('ascii', 'ignore').decode('ascii')
            f.write(output)