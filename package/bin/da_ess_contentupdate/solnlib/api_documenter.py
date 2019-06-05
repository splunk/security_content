# Copyright 2016 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License'): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

'''
This module provides decorators for api documentation.


Module for generating splunk custom rest endpoint api documentation
Currently this module generates the api documentation for
swagger representation (http://swagger.io/).
Users should add the decorators to the api methods
to generate the documentation.

Usage::
    >>> from solnlib.api_documenter import api, api_operation,\
      api_response, api_path_param, api_body_param, api_get_spec
    >>> from schematics.models import Model

    >>> @api_model(True)
    >>> class Example(Model):
    >>>     # your model class (pojo) with all the params
    >>>     pass

    >>> class ApiExampleRestHandler(rest.BaseRestHandler):
    >>>     @api()
    >>>     def __init__(self, *args, **kwargs):
    >>>        rest.BaseRestHandler.__init__(self, *args, **kwargs)


    >>>     @api_operation(http_method='get',\
    description='get all records', action='get_all')
    >>>     @api_response(code=200, ref='Example', is_list=True)
    >>>     @api_response(code=400)
    >>>     def handle_GET(self):
    >>>         # This is to generate the spec file for swagger representation
    >>>         if self.context['query'].get('spec'):
    >>>             self.response.write(str(get_spec(self.context,\
    ['GET', 'PUT', 'POST', 'DELETE'])))
    >>>             return
    >>>         else:
    >>>             # your code
    >>>             pass

    >>>     @api_operation(http_method='put',\
    description='Create a new record.', action='create')
    >>>     @api_body_param(is_model_class_used=True, ref='Example',\
     is_list=False)
    >>>     @api_response(code=200, ref='Example', is_list=False)
    >>>     @api_response(code=400)
    >>>     def handle_PUT(self):
    >>>         # your code
    >>>         pass

    >>>     @api_operation(http_method='post',\
    description='update existing record by id', action='update')
    >>>     @api_path_param()
    >>>     @api_body_param(is_model_class_used=True, ref='Example',\
     is_list=False)
    >>>     @api_response(code=200, ref='Example', is_list=False)
    >>>     @api_response(code=400)
    >>>     def handle_POST(self):
    >>>         # your code
    >>>         pass


    >>>     @api_operation(http_method='delete',\
    description='delete a record by its id', action='delete')
    >>>     @api_path_param()
    >>>     @api_response(code=200, ref='delete', is_list=False)
    >>>     @api_response(code=400)
    >>>     def handle_DELETE(self):
    >>>         # your code
    >>>         pass

Note:
Whenever placing decorators over an operation,
you must have an @api_operation on top
and an @api_response operation on the bottom. You can stack multiple
sets of the decorators on top of each other,
each with different combinations of parameters.
The @api_model can be placed anywhere on this stack, unless you are using
model classes in which case it should be placed over each model class.
'''

import json
import os
import os.path as op
import re
import tempfile

from . import splunk_rest_client as rest
from .packages import simpleyaml as yaml

__all__ = ['api',
           'api_model',
           'api_operation',
           'api_response',
           'api_body_param',
           'api_get_spec',
           'api_path_param',
           'api_query_param']


def api_model(is_model_class_used, req=None, ref=None, obj=None):
    '''Creates a definition based on a model class (pojo).

    :param is_model_class_used: True if model class (pojo) is being used,
     false otherwise.
    :type: ```bool```
    :param req: A list of required params for api method.
     This parameter is optional if is_model_class_used is true.
    :type: ```list```
    :param ref: This is the name of the definition in the YAML spec.\
    For example, #/definitions/ref.\
    This parameter is optional if is_model_class_used is true.
    :type: ```basestring```
    :param obj: This is the model itself in the form of a dictionary.\
    It is optional if is_model_class_used is True.
    :type: ```dict```
    '''
    def decorator(cls):
        if not spec.paths:
            return cls
        if is_model_class_used:
            params = vars(cls).items()
            definition = {}
            # FixMe: (later) No need to replace.
            name = cls.__name__.replace("Model", "")
            fields = None
            # grab fields
            for param in params:
                if param[0] == '_field_list':
                    fields = param[1]
            # create dictionary of definition to be added
            if fields:
                for field in fields:
                    definition[field[0]] = field[1]
            spec.create_model(definition, name, req)
        else:
            definition = {'type': 'object', 'required': req, 'properties': obj}
            spec.add_definition(ref, definition)
        generator.write_temp()
        return cls
    return decorator


def api_operation(http_method, description=None, action=None):
    '''Specify the http method used by the api

    :param http_method: The http method of the operation.\
    Valid values include get, put, post or delete.
    :type: ```basestring```
    :param description: (optional) A description of the operation.
    :type: ```basestring`````
    :param action: (optional)  The specific name of the operation,\
    for example get_all.
    :type: ```basestring```
    '''
    def decorator(fn):
        def operation(*args, **kwargs):
            if not spec.paths:
                return fn(None, http_method, None, *args, **kwargs)
            op = {}
            tag = spec.get_path().replace("/{id}", "").replace("/", "-")
            op['tags'] = [tag]
            if description:
                op['description'] = description
            if action:
                op['operationId'] = action
            # create empty list for parameters
            op['parameters'] = []
            return fn(spec.get_path(), http_method, op, *args, **kwargs)
        return operation
    return decorator


def api_path_param():
    '''Documents the path parameter

    '''
    def decorator(fn):
        def wrapper(path, name, op, *args, **kwargs):
            if not spec.paths:
                return fn(path, name, op, *args, **kwargs)
            if path.find("/{id}") == -1:
                path = path + "/{id}"

            # add path if it doesn't already exist
            if path not in spec.paths:
                spec.add_path(path)
            param = {
                "name": "id",
                "in": "path",
                "required": True,
                "type": "string"
            }
            op['parameters'].append(param)
            return fn(path, name, op, *args, **kwargs)
        return wrapper
    return decorator


def api_body_param(is_model_class_used, ref, is_list=False):
    '''Documents the body parameter.

    :param is_model_class_used:\
    True is model class is being used and false otherwise.
    :type: ```bool```
    :param ref: This is the name of the definition in the YAML spec.\
    For example, #/definitions/ref.
    :type: ```basestring```
    :param is_list:\
    True if the body parameter is in the form of a list or array.\
    Defaults to false.
    :type: ```bool```
    '''
    def decorator(fn):
        def wrapper(path, name, op, *args, **kwargs):
            if not spec.paths:
                return fn(path, name, op, *args, **kwargs)
            param = {
                "name": "body",
                "in": "body",
                "required": True
            }
            if is_list:
                param['schema'] = {
                    'type': 'array', 'items': {
                        '$ref': '#/definitions/' + ref}}
            else:
                param['schema'] = {'$ref': '#/definitions/' + ref}
            # add parameter to operation
            op['parameters'].append(param)
            return fn(path, name, op, *args, **kwargs)
        return wrapper
    return decorator


def api_query_param(params):
    '''Documents the query parameters

    :param params: parameters list
    :type: ```list```
    '''
    def decorator(fn):
        def wrapper(path, name, op, *args, **kwargs):
            if not spec.paths:
                return fn(path, name, op, *args, **kwargs)
            for k in params:
                param = {
                    "name": k,
                    "in": "query",
                    "required": False,
                    "type": 'string'
                }
                # add parameter to operation
                op['parameters'].append(param)

            return fn(path, name, op, *args, **kwargs)
        return wrapper
    return decorator


def api_response(code, ref=None, is_list=None):
    '''Document the response for an operation.

    :param code: The api response code ie. 200, 400.
    :type: ```int```
    :param ref: (optional)\
    This is the name of the definition in the YAML spec.\
    For example, #/definitions/ref.
    :type: ```basestring```
    :param is_list: (optional)\
    True if the body parameter is in the form of a list or array.\
    Defaults to false.
    :type: ```bool```
    '''
    def decorator(fn):
        def wrapper(path, name, op, *args, **kwargs):
            if not spec.paths:
                if fn.__name__ == 'wrapper':
                    return fn(path, name, op, *args, **kwargs)
                else:
                    return fn(*args, **kwargs)
            # response code map
            code_map = {
                200: 'OK',
                201: 'Created',
                202: 'Accepted',
                400: 'Bad Request',
                401: 'Unauthorized',
                403: 'Forbidden',
                404: 'Not Found'
            }
            # begin making response object
            response = {code: {'description': code_map[code]}}
            if ref:
                if is_list:
                    response[code]['schema'] = {
                        'type': 'array', 'items': {
                            '$ref': '#/definitions/' + ref}}
                else:
                    response[code]['schema'] = \
                        {'$ref': '#/definitions/' + ref}
            if 'responses' not in op:
                op['responses'] = response
            else:
                op['responses'][code] = response[code]
            if fn.__name__ == 'wrapper':
                return fn(path, name, op, *args, **kwargs)
            elif fn.__name__ == 'operation':
                spec.add_operation(path, name, op)
                generator.write_temp()
                return fn(*args, **kwargs)
            else:
                spec.add_operation(path, name, op)
                generator.write_temp()
                return fn(*args, **kwargs)
        return wrapper
    return decorator


def api():
    '''Sets the info and paths for the specification.

    This must be place above the
    rest.BaseRestHandler subclass's __init__ function.
    '''
    def decorator(fn):
        def wrapper(*args, **kwargs):
            # only write spec if it is asked for
            if len(args) > 2 and 'spec' not in args[2]['query']:
                fn(*args, **kwargs)
                return
            if len(args) > 2 and args[2]['path']:
                path_keys = [
                    '',
                    'services',
                    'app',
                    'version',
                    'api',
                    'id',
                    'action']
                path_params = dict(zip(path_keys, args[2]['path'].split('/')))
                app = path_params.get('app')
                version = path_params.get('version')
                api_name = path_params.get('api')
                spec.set_version(version)
                spec.set_title("")
                if args[2]['headers'] and args[2]['headers']['x-request-url']:
                    host_url = args[2]['headers']['x-request-url']
                    if host_url and len(host_url) > 0:
                        base_host_url = host_url.split('/services/')[0]
                        url = base_host_url.split('://')
                        if url and len(url) > 1:
                            spec.set_schemes(url[0])
                            spec.set_host(url[1] + "/services/")
                            spec.add_path(app + "/" + version + "/" + api_name)
                            generator.write_temp()
            fn(*args, **kwargs)
            return
        return wrapper
    return decorator


def api_get_spec(context, method_list):
    '''Generates and Returns the spec file data
    :param context: Dictionary with app, session, version and api fields
    :type: ```dict```
    :param method_list: List of API methods to call
    :type: ```list```
    :return: generated spec file
    :rtype: ```basestring```
    '''
    _generate_documentation(context, method_list)
    with open(tempfile.gettempdir() + op.sep + 'spec.yaml') as stream:
        try:
            spec_file = yaml.load(stream)
        except yaml.YAMLError as ex:
            raise Exception("Please try again. Exception: {}".format(ex))
        return json.dumps(spec_file)


def _generate_documentation(context, method_list):
    '''Generates documentation spec file by calling api methods
    :param context: Dict with app, session, version and api fields
    :param method_list: List of API methods to call
    '''
    uri = '/services/{}/{}/{}'.format(context.get('app'),
                                      context.get('version'),
                                      context.get('api'))
    _rest_client = rest.SplunkRestClient(context.get('session'), app='-')

    for method in method_list:
        try:
            _rest_client.request(uri, owner=context.get('session'),
                                 method=method)
        except Exception as e:
            pass
    generator.update_spec()


class _SwaggerSpecGenerator(object):
    '''Private class to generate the swagger spec file.
    '''

    def __init__(self, swagger_api):
        self.api = swagger_api
        self.order = [
            "swagger",
            "info",
            "host",
            "schemes",
            "consumes",
            "produces",
            "paths",
            "definitions"]

    def write_temp(self):
        '''
        Stores changes to the spec in a temp file.
        '''
        spec = {
            "swagger": self.api.__getattribute__('swagger'),
            "info": self.api.__getattribute__('info'),
            "host": self.api.__getattribute__('host'),
            "schemes": self.api.__getattribute__('schemes'),
            "consumes": self.api.__getattribute__('consumes'),
            "produces": self.api.__getattribute__('produces'),
            "paths": self.api.__getattribute__('paths'),
            "definitions": self.api.__getattribute__('definitions')
        }

        stream = file((tempfile.gettempdir() + op.sep + 'temp.yaml'), 'w')
        for x in self.order:
            yaml.dump({x: spec[x]}, stream, default_flow_style=False)

    def update_spec(self):
        '''
        Updates the specification from the temp file.
        '''
        try:
            os.rename(
                tempfile.gettempdir() +
                op.sep +
                'temp.yaml',
                tempfile.gettempdir() +
                op.sep +
                'spec.yaml')
        except Exception as e:
            raise Exception(
                "Spec file not found, please try again."
                " Exception: {}".format(e))


class _SwaggerApi(object):
    '''
    Private class to generate the swagger
     documentation and default params values.
    '''

    def __init__(self):
        if op.isfile(tempfile.gettempdir() + op.sep + 'temp.yaml'):
            with open(tempfile.gettempdir() + op.sep + 'temp.yaml', "r")\
                    as stream:
                try:
                    spec = yaml.load(stream)
                    self.swagger = spec["swagger"]
                    self.info = spec["info"]
                    self.host = spec["host"]
                    self.schemes = spec["schemes"]
                    self.consumes = spec["consumes"]
                    self.produces = spec["produces"]
                    self.paths = spec["paths"]
                    self.definitions = spec["definitions"]
                except yaml.YAMLError as e:
                    raise Exception(
                        "Please retry again. Exception: {}".format(e))
        else:
            self.swagger = "2.0"
            self.info = {
                "description": ""
            }
            self.host = None
            self.schemes = ["http"]
            self.consumes = ["application/json"]
            self.produces = ["application/json"]
            self.paths = {}
            self.definitions = {}
        self.type_converter = {
            "BooleanType": "boolean",
            "CustomStringType": "string",
            "StringType": "string",
            "IntType": "integer",
            "FloatType": "float",
            "DictType": "object",
            "LongType": "long",
            "DateTimeType": "dateTime"
        }
        self.default_values = {
            'integer': 0,
            'float': 0.0,
            'double': 0.0,
            'string': '',
            'binary': '0b',
            'boolean': False,
            'long': 0,
            'dateTime': 0.0,
            'byte': ''
        }
        self.swagger_types = {
            "integer": "integer",
            "long": "integer",
            "float": "number",
            "double": "number",
            "string": "string",
            "binary": "string",
            "dateTime": "string",
            "boolean": "boolean",
            "byte": "string"
        }

    def get_path(self):
        '''
        gets the API name from paths keys
        :return: api path
        :rtype: ```basestring```
        '''
        if self.paths and self.paths.keys() and len(self.paths.keys()) > 0:
            return self.paths.keys()[0]

    def set_title(self, title):
        '''
        Sets API title
        :param title: title
        :type: ```basestring```
        '''
        self.info['title'] = title

    def set_version(self, version):
        '''
        Sets API version
        :param version: version
        :type: ```basestring```
        '''
        self.info['version'] = version

    def set_host(self, host):
        '''
        Sets the HOST name
        :param host: host name
        :type: ```basestring```
        '''
        self.host = host

    def set_schemes(self, scheme):
        '''
        sets schemes for host (http/https)
        :param scheme: scheme
        :type: ```basestring```
        '''
        self.schemes = [scheme]

    def add_operation(self, path, name, op):
        '''
        Add a new operation to the api spec.
        :param path: API path
        :type: ```basestring```
        :param name: name of the operation
        :type: ```basestring```
        :param op: operation
        :type: ```basestring```
        '''
        if path and name:
            self.paths[path][name] = op

    def add_path(self, path):
        '''
        Add a new path to the api spec.
        :param path: API path
        :type: ```basestring```
        '''
        if path not in self.paths:
            self.paths[path] = {}

    def add_definition(self, name, definition):
        '''
        Add a new definition to the api spec.
        :param name: name of the input
        :type: ```basestring```
        :param definition: definition properties
        :type: ```dict```
        '''
        self.add_examples(definition['properties'])
        self.fix_types(definition['properties'])
        self.definitions[name] = definition

    def create_model(self, params, name, req):
        '''
        Create a model to be added to the definitions of the spec.
        :param params: Request params
        :type: ```dict```
        :param name: name of the class
        :type: ```basestring```
        :param req:  list of required params for api method
        :type: ```list```
        '''
        # convert given dict to a formatted one
        definition = {"properties": {}}
        # add requirements if given
        if req:
            definition["requirements"] = req
        for param in params:
            # get type of property
            type_info = re.findall(
                '\((.*?)\)\s', str(params.get(param)), re.DOTALL)
            if type_info and len(type_info) > 0:
                type_info = type_info[0]
            prop_type = re.findall(
                '\<(.*?)\(', str(params.get(param)), re.DOTALL)
            if prop_type and len(prop_type) > 0:
                prop_type = prop_type[0]
            if prop_type in self.type_converter:
                definition["properties"][param] = {
                    "type": self.type_converter[prop_type]}
            # check for array
            elif prop_type == 'ListType':
                if type_info != 'ModelType':
                    definition["properties"][param] = {"type": 'array'}
                    definition["properties"][param]['items'] = {
                        'type': self.type_converter[type_info]}
            else:
                ref = type_info.replace("Model", "")
                definition["properties"][param] = {"$ref": ref}
        self.add_definition(name, definition)

    def add_examples(self, properties):
        '''
        Add examples to documentation for a definition
        :param properties: Default request params
        :type: ```dict```
        '''
        for prop in properties:
            if 'type' in properties[prop] and properties[prop][
                    'type'] in self.default_values\
                    and 'example' not in properties[prop]:
                properties[prop]['example'] = self.default_values[
                    properties[prop]['type']]

    def fix_types(self, properties):
        '''
        Fix types to make the spec Open API compliant.
        :param properties: Default request param properties
        :type: ```dict```
        '''
        for prop in properties:
            if 'type' in properties[prop] and properties[
                    prop]['type'] in self.swagger_types:
                if properties[prop]['type'] != self.swagger_types[
                        properties[prop]['type']]:
                    properties[prop]['format'] = properties[prop]['type']
                    properties[prop]['type'] = self.swagger_types[
                        properties[prop]['type']]
            if '$ref' in properties[prop]:
                properties[prop]['$ref'] = '#/definitions/' + \
                    properties[prop]['$ref']

spec = _SwaggerApi()
generator = _SwaggerSpecGenerator(spec)
