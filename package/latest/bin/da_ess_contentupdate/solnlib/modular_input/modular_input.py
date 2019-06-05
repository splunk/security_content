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
This module provides a base class of Splunk modular input.
'''

import logging
import sys
import traceback
import urllib2
from abc import ABCMeta, abstractmethod

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from ..packages.splunklib import binding
from ..packages.splunklib.modularinput.argument import Argument
from ..packages.splunklib.modularinput.scheme import Scheme
from ..packages.splunklib.modularinput.input_definition import InputDefinition
from ..packages.splunklib.modularinput.validation_definition import ValidationDefinition

from .. import utils
from . import checkpointer
from . import event_writer
from ..orphan_process_monitor import OrphanProcessMonitor

__all__ = ['ModularInputException',
           'ModularInput']


class ModularInputException(Exception):
    pass


class ModularInput(object):
    '''Base class of Splunk modular input.

    It's a base modular input, it should be inherited by sub modular input. For
    sub modular input, properties: 'app', 'name', 'title' and 'description' must
    be overriden, also there are some other optional properties can be overriden
    like: 'use_external_validation', 'use_single_instance', 'use_kvstore_checkpointer'
    and 'use_hec_event_writer'.

    Notes: If you set 'KVStoreCheckpointer' or 'use_hec_event_writer' to True,
    you must override the corresponding 'kvstore_checkpointer_collection_name'
    and 'hec_input_name'.

    Usage::

       >>> Class TestModularInput(ModularInput):
       >>>     app = 'TestApp'
       >>>     name = 'test_modular_input'
       >>>     title = 'Test modular input'
       >>>     description = 'This is a test modular input'
       >>>     use_external_validation = True
       >>>     use_single_instance = False
       >>>     use_kvstore_checkpointer = True
       >>>     kvstore_checkpointer_collection_name = 'TestCheckpoint'
       >>>     use_hec_event_writer = True
       >>>     hec_input_name = 'TestEventWriter'
       >>>
       >>>     def extra_arguments(self):
       >>>         ... .. .
       >>>
       >>>     def do_validation(self, parameters):
       >>>         ... .. .
       >>>
       >>>     def do_run(self, inputs):
       >>>         ... .. .
       >>>
       >>> if __name__ == '__main__':
       >>>     md = TestModularInput()
       >>>     md.execute()
    '''

    __metaclass__ = ABCMeta

    # App name, must be overriden
    app = None
    # Modular input name, must be overriden
    name = None
    # Modular input scheme title, must be overriden
    title = None
    # Modular input scheme description, must be overriden
    description = None
    # Modular input scheme use external validation, default is False
    use_external_validation = False
    # Modular input scheme use single instance mode, default is False
    use_single_instance = False
    # Use kvstore as checkpointer, default is True
    use_kvstore_checkpointer = True
    # Collection name of kvstore checkpointer, must be overriden if
    # use_kvstore_checkpointer is True
    kvstore_checkpointer_collection_name = None
    # Use hec event writer
    use_hec_event_writer = True
    # Input name of Splunk HEC, must be overriden if use_hec_event_writer
    # is True
    hec_input_name = None

    def __init__(self):
        # Validate properties
        self._validate_properties()
        # Modular input state
        self.should_exit = False
        # Metadata
        self.server_host_name = None
        self.server_uri = None
        self.server_scheme = None
        self.server_host = None
        self.server_port = None
        self.session_key = None
        # Modular input config name
        self.config_name = None
        # Checkpoint dir
        self._checkpoint_dir = None
        # Checkpointer
        self._checkpointer = None
        # Orphan process monitor
        self._orphan_monitor = None
        # Event writer
        self._event_writer = None

    def _validate_properties(self):
        if not all([self.app, self.name, self.title, self.description]):
            raise ModularInputException(
                'Attributes: "app", "name", "title", "description" must '
                'be overriden.')

        if self.use_kvstore_checkpointer:
            if self.kvstore_checkpointer_collection_name is None:
                raise ModularInputException(
                    'Attribute: "kvstore_checkpointer_collection_name" must'
                    'be overriden if "use_kvstore_checkpointer" is True".')
            elif self.kvstore_checkpointer_collection_name.strip() == '':
                raise ModularInputException(
                    'Attribute: "kvstore_checkpointer_collection_name" can'
                    ' not be empty.')

        if self.use_hec_event_writer:
            if self.hec_input_name is None:
                raise ModularInputException(
                    'Attribute: "hec_input_name" must be overriden '
                    'if "use_hec_event_writer" is True.')
            elif self.hec_input_name.strip() == '':
                raise ModularInputException(
                    'Attribute: "hec_input_name" can not be empty.')

    @property
    def checkpointer(self):
        '''Get checkpointer object.

        The checkpointer returned depends on use_kvstore_checkpointer flag,
        if use_kvstore_checkpointer is true will return an KVStoreCheckpointer
        object else an FileCheckpointer object.

        :returns: An checkpointer object.
        :rtype: ``Checkpointer object``
        '''

        if self._checkpointer is not None:
            return self._checkpoint_dir

        self._checkpointer = self._create_checkpointer()
        return self._checkpointer

    def _create_checkpointer(self):
        if self.use_kvstore_checkpointer:
            checkpointer_name = ':'.join(
                [self.app, self.config_name,
                 self.kvstore_checkpointer_collection_name])
            try:
                return checkpointer.KVStoreCheckpointer(
                    checkpointer_name, self.session_key,
                    self.app, owner='nobody', scheme=self.server_scheme,
                    host=self.server_host, port=self.server_port)
            except binding.HTTPError as e:
                logging.error('Failed to init kvstore checkpointer: %s.',
                              traceback.format_exc(e))
                raise
        else:
            return checkpointer.FileCheckpointer(self._checkpoint_dir)

    @property
    def event_writer(self):
        '''Get event writer object.

        The event writer returned depends on use_hec_event_writer flag,
        if use_hec_event_writer is true will return an HECEventWriter
        object else an ClassicEventWriter object.

        :returns: Event writer object.
        :rtype: ``EventWriter object``
        '''

        if self._event_writer is not None:
            return self._event_writer

        self._event_writer = self._create_event_writer()
        return self._event_writer

    def _create_event_writer(self):
        if self.use_hec_event_writer:
            hec_input_name = ':'.join([self.app, self.hec_input_name])
            try:
                return event_writer.HECEventWriter(
                    hec_input_name, self.session_key,
                    scheme=self.server_scheme, host=self.server_host,
                    port=self.server_port)
            except binding.HTTPError as e:
                logging.error('Failed to init HECEventWriter: %s.',
                              traceback.format_exc(e))
                raise
        else:
            return event_writer.ClassicEventWriter()

    def _update_metadata(self, metadata):
        self.server_host_name = metadata['server_host']
        splunkd = urllib2.urlparse.urlsplit(metadata['server_uri'])
        self.server_uri = splunkd.geturl()
        self.server_scheme = splunkd.scheme
        self.server_host = splunkd.hostname
        self.server_port = splunkd.port
        self.session_key = metadata['session_key']
        self._checkpoint_dir = metadata['checkpoint_dir']

    def _do_scheme(self):
        scheme = Scheme(self.title)
        scheme.description = self.description
        scheme.use_external_validation = self.use_external_validation
        scheme.streaming_mode = Scheme.streaming_mode_xml
        scheme.use_single_instance = self.use_single_instance

        for argument in self.extra_arguments():
            name = argument['name']
            title = argument.get('title', None)
            description = argument.get('description', None)
            validation = argument.get('validation', None)
            data_type = argument.get('data_type', Argument.data_type_string)
            required_on_edit = argument.get('required_on_edit', False)
            required_on_create = argument.get('required_on_create', False)

            scheme.add_argument(
                Argument(name, title=title, description=description,
                         validation=validation, data_type=data_type,
                         required_on_edit=required_on_edit,
                         required_on_create=required_on_create))

        return ET.tostring(scheme.to_xml())

    def extra_arguments(self):
        '''Extra arguments for modular input.

        Default implementation is returning an empty list.

        :returns: List of arguments like: [{'name': 'arg1',
                                            'title': 'arg1 title',
                                            'description': 'arg1 description',
                                            'validation': 'arg1 validation statement',
                                            'data_type': Argument.data_type_string,
                                            'required_on_edit': False,
                                            'required_on_create': False},
                                            {...},
                                            {...}]
        :rtype: ``list``
        '''

        return []

    def do_validation(self, parameters):
        '''Handles external validation for modular input kinds.

        When Splunk calls a modular input script in validation mode, it will
        pass in an XML document giving information about the Splunk instance
        (so you can call back into it if needed) and the name and parameters
        of the proposed input. If this function does not throw an exception,
        the validation is assumed to succeed. Otherwise any errors thrown will
        be turned into a string and logged back to Splunk.

        :param parameters: The parameters of input passed by splunkd.

        :raises Exception: If validation is failed.
        '''

        pass

    @abstractmethod
    def do_run(self, inputs):
        '''Runs this modular input

        :param inputs: Command line arguments passed to this modular input.
            For single instance mode, inputs like: {
            'stanza_name1': {'arg1': 'arg1_value', 'arg2': 'arg2_value', ...}
            'stanza_name2': {'arg1': 'arg1_value', 'arg2': 'arg2_value', ...}
            'stanza_name3': {'arg1': 'arg1_value', 'arg2': 'arg2_value', ...}
            }.
            For multile instance mode, inputs like: {
            'stanza_name1': {'arg1': 'arg1_value', 'arg2': 'arg2_value', ...}
            }.
        :type inputs: ``dict``
        '''

        pass

    def register_teardown_handler(self, handler, *args):
        '''Register teardown signal handler.

        :param handler: Teardown signal handler.

        Usage::
           >>> mi = ModularInput(...)
           >>> def teardown_handler(arg1, arg2, ...):
           >>>     ...
           >>> mi.register_teardown_handler(teardown_handler, arg1, arg2, ...)
        '''

        def _teardown_handler(signum, frame):
            handler(*args)

        utils.handle_teardown_signals(_teardown_handler)

    def register_orphan_handler(self, handler, *args):
        '''Register orphan process handler.

        :param handler: Orphan process handler.

        Usage::
           >>> mi = ModularInput(...)
           >>> def orphan_handler(arg1, arg2, ...):
           >>>     ...
           >>> mi.register_orphan_handler(orphan_handler, arg1, arg2, ...)
        '''

        def _orphan_handler():
            handler(*args)

        if self._orphan_monitor is None:
            self._orphan_monitor = OrphanProcessMonitor(_orphan_handler)
            self._orphan_monitor.start()

    def get_validation_definition(self):
        '''Get validation definition.

        This method can be overwritten to get validation definition from
        other input instead `stdin`.

        :returns: A dict object must contains `metadata` and `parameters`,
            example: {
            'metadata': {
            'session_key': 'iCKPS0cvmpyeJk...sdaf',
            'server_host': 'test-test.com',
            'server_uri': 'https://127.0.0.1:8089',
            'checkpoint_dir': '/tmp'
            },
            parameters: {'args1': value1, 'args2': value2}
            }
        :rtype: ``dict``
        '''

        validation_definition = ValidationDefinition.parse(sys.stdin)
        return {
            'metadata': validation_definition.metadata,
            'parameters': validation_definition.parameters
        }

    def get_input_definition(self):
        '''Get input definition.

        This method can be overwritten to get input definition from
        other input instead `stdin`.

        :returns: A dict object must contains `metadata` and `inputs`,
            example: {
            'metadata': {
            'session_key': 'iCKPS0cvmpyeJk...sdaf',
            'server_host': 'test-test.com',
            'server_uri': 'https://127.0.0.1:8089',
            'checkpoint_dir': '/tmp'
            },
            inputs: {
            'stanza1': {'arg1': value1, 'arg2': value2},
            'stanza2': {'arg1': value1, 'arg2': value2}
            }
            }
        :rtype: ``dict``
        '''

        input_definition = InputDefinition.parse(sys.stdin)
        return {
            'metadata': input_definition.metadata,
            'inputs': input_definition.inputs
        }

    def execute(self):
        '''Modular input entry.

        Usage::
           >>> Class TestModularInput(ModularInput):
           >>>         ... .. .
           >>>
           >>> if __name__ == '__main__':
           >>>     md = TestModularInput()
           >>>     md.execute()
        '''

        if len(sys.argv) == 1:
            try:
                input_definition = self.get_input_definition()
                self._update_metadata(input_definition['metadata'])
                if self.use_single_instance:
                    self.config_name = self.name
                else:
                    self.config_name = input_definition['inputs'].keys()[0]
                self.do_run(input_definition['inputs'])
                logging.info('Modular input: %s exit normally.', self.name)
                return 0
            except Exception as e:
                logging.error('Modular input: %s exit with exception: %s.',
                              self.name, traceback.format_exc(e))
                return 1
            finally:
                # Stop orphan monitor if any
                if self._orphan_monitor:
                    self._orphan_monitor.stop()

        elif str(sys.argv[1]).lower() == '--scheme':
            sys.stdout.write(self._do_scheme())
            sys.stdout.flush()
            return 0

        elif sys.argv[1].lower() == '--validate-arguments':
            try:
                validation_definition = self.get_validation_definition()
                self._update_metadata(validation_definition['metadata'])
                self.do_validation(validation_definition['parameters'])
                return 0
            except Exception as e:
                logging.error(
                    'Modular input: %s validate arguments with exception: %s.',
                    self.name, traceback.format_exc(e))
                root = ET.Element('error')
                ET.SubElement(root, 'message').text = str(e)
                sys.stderr.write(ET.tostring(root))
                sys.stderr.flush()
                return 1
        else:
            logging.error(
                'Modular input: %s run with invalid arguments: "%s".',
                self.name, ' '.join(sys.argv[1:]))
            return 1
