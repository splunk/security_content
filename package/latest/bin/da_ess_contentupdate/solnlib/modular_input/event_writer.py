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
This module provides two kinds of event writers (ClassicEventWriter,
HECEventWriter) to write Splunk modular input events.
'''

import logging
import sys
import threading
import time
import traceback
from abc import ABCMeta, abstractmethod

from .event import XMLEvent, HECEvent
from .. import splunk_rest_client as rest_client
from .. import utils
from ..hec_config import HECConfig
from ..packages.splunklib import binding
from ..splunkenv import get_splunkd_access_info
from ..utils import retry

__all__ = ['ClassicEventWriter',
           'HECEventWriter']


class EventWriter(object):
    '''Base class of event writer.
    '''

    __metaclass__ = ABCMeta

    description = 'EventWriter'

    @abstractmethod
    def create_event(self, data, time=None,
                     index=None, host=None, source=None, sourcetype=None,
                     stanza=None, unbroken=False, done=False):
        '''Create a new event.

        :param data: Event data.
        :type data: ``json object``
        :param time: (optional) Event timestamp, default is None.
        :type time: ``float``
        :param index: (optional) The index event will be written to, default
            is None
        :type index: ``string``
        :param host: (optional) Event host, default is None.
        :type host: ``string``
        :param source: (optional) Event source, default is None.
        :type source: ``string``
        :param sourcetype: (optional) Event sourcetype, default is None.
        :type sourcetype: ``string``
        :param stanza: (optional) Event stanza name, default is None.
        :type stanza: ``string``
        :param unbroken: (optional) Event unbroken flag, default is False.
            It is only meaningful when for XMLEvent when using ClassicEventWriter.
        :type unbroken: ``bool``
        :param done: (optional) The last unbroken event, default is False.
            It is only meaningful when for XMLEvent when using ClassicEventWriter.
        :returns: ``bool``
        :returns: A new event object.
        :rtype: ``(XMLEvent, HECEvent)``

        Usage::
           >>> ew = event_writer.HECEventWriter(...)
           >>> event = ew.create_event(
           >>>     data='This is a test data.',
           >>>     time='%.3f' % 1372274622.493,
           >>>     index='main',
           >>>     host='localhost',
           >>>     source='Splunk',
           >>>     sourcetype='misc',
           >>>     stanza='test_scheme://test',
           >>>     unbroken=True,
           >>>     done=True)
        '''

        pass

    @abstractmethod
    def write_events(self, events):
        '''Write events.

        :param events: List of events to write.
        :type events: ``list``

        Usage::
           >>> from solnlib.modular_input import event_writer
           >>> ew = event_writer.EventWriter(...)
           >>> ew.write_events([event1, event2])
        '''

        pass


class ClassicEventWriter(EventWriter):
    '''Classic event writer.

    Use sys.stdout as the output.

    :param lock: (optional) lock to exclusively access stdout.
        by default, it is None and it will use threading safe lock.
        if user would like to make the lock multiple-process safe, user should
        pass in multiprocessing.Lock() instead
    :type lock: ``theading.Lock or multiprocessing.Lock``

    Usage::
        >>> from solnlib.modular_input import event_writer
        >>> ew = event_writer.ClassicEventWriter()
        >>> ew.write_events([event1, event2])
    '''

    description = 'ClassicEventWriter'

    def __init__(self, lock=None):
        if lock is None:
            self._lock = threading.Lock()
        else:
            self._lock = lock

    def create_event(self, data, time=None,
                     index=None, host=None, source=None, sourcetype=None,
                     stanza=None, unbroken=False, done=False):
        '''Create a new XMLEvent object.
        '''

        return XMLEvent(
            data, time=time,
            index=index, host=host, source=source, sourcetype=sourcetype,
            stanza=stanza, unbroken=unbroken, done=done)

    def write_events(self, events):
        if not events:
            return

        stdout = sys.stdout

        data = ''.join([event for event in XMLEvent.format_events(events)])
        with self._lock:
            stdout.write(data)
            stdout.flush()


class HECEventWriter(EventWriter):
    '''Classic event writer.

    Use Splunk HEC as the output.

    :param hec_input_name: Splunk HEC input name.
    :type hec_input_name: ``string``
    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param hec_uri: (optional) If hec_uri and hec_token are provided, they will
       higher precedence than hec_input_name
    :type hec_token: ``string``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``

    Usage::
        >>> from solnlib.modular_input import event_writer
        >>> ew = event_writer.HECEventWriter(hec_input_name, session_key)
        >>> ew.write_events([event1, event2])
    '''

    WRITE_EVENT_RETRIES = 3
    HTTP_INPUT_CONFIG_ENDPOINT = \
        '/servicesNS/nobody/splunk_httpinput/data/inputs/http'
    HTTP_EVENT_COLLECTOR_ENDPOINT = '/services/collector'

    description = 'HECEventWriter'

    headers = [('Content-Type', 'application/json')]

    def __init__(self, hec_input_name, session_key,
                 scheme=None, host=None, port=None, hec_uri=None,
                 hec_token=None, **context):
        super(HECEventWriter, self).__init__()
        self._session_key = session_key

        if not all([scheme, host, port]):
            scheme, host, port = get_splunkd_access_info()

        if hec_uri and hec_token:
            scheme, host, hec_port = utils.extract_http_scheme_host_port(
                hec_uri)
        else:
            hec_port, hec_token = self._get_hec_config(
                hec_input_name, session_key, scheme, host, port, **context)

        if not context.get('pool_connections'):
            context['pool_connections'] = 10

        if not context.get('pool_maxsize'):
            context['pool_maxsize'] = 10

        self._rest_client = rest_client.SplunkRestClient(hec_token,
                                                         app='-',
                                                         scheme=scheme,
                                                         host=host,
                                                         port=hec_port,
                                                         **context)

    @staticmethod
    def create_from_token(hec_uri, hec_token, **context):
        '''Given HEC URI and HEC token, create HECEventWriter object.
        This function simplifies the standalone mode HECEventWriter usage
        (not in a modinput)

        :param hec_uri: Http Event Collector URI, like https://localhost:8088
        :type hec_uri: ``string``
        :param hec_token: Http Event Collector token
        :type hec_token: ``string``
        :param context: Other configurations.
        :type context: ``dict``
        '''

        return HECEventWriter(
            None, None, None, None, None, hec_uri=hec_uri, hec_token=hec_token,
            **context)

    @staticmethod
    def create_from_input(hec_input_name, splunkd_uri, session_key, **context):
        '''Given HEC input stanza name, splunkd URI and splunkd session key,
        create HECEventWriter object. HEC URI and token etc will be discovered
        from HEC input stanza. When hitting HEC event limit, the underlying
        code will increase the HEC event limit automatically by calling
        corresponding REST API against splunkd_uri by using session_key

        :param hec_input_name: Splunk HEC input name.
        :type hec_input_name: ``string``
        :param splunkd_uri: Splunkd URI, like https://localhost:8089
        :type splunkd_uri: ``string``
        :param session_key: Splunkd access token.
        :type session_key: ``string``
        :param context: Other configurations.
        :type context: ``dict``
        '''

        scheme, host, port = utils.extract_http_scheme_host_port(splunkd_uri)
        return HECEventWriter(
            hec_input_name, session_key, scheme, host, port, **context)

    @staticmethod
    def create_from_token_with_session_key(
            splunkd_uri, session_key, hec_uri, hec_token, **context):
        '''Given Splunkd URI, Splunkd session key, HEC URI and HEC token,
        create HECEventWriter object. When hitting HEC event limit, the event
        writer will increase the HEC event limit automatically by calling
        corresponding REST API against splunkd_uri by using session_key

        :param splunkd_uri: Splunkd URI, like https://localhost:8089
        :type splunkd_uri: ``string``
        :param session_key: Splunkd access token.
        :type session_key: ``string``
        :param hec_uri: Http Event Collector URI, like https://localhost:8088
        :type hec_uri: ``string``
        :param hec_token: Http Event Collector token
        :type hec_token: ``string``
        :param context: Other configurations.
        :type context: ``dict``
        '''

        scheme, host, port = utils.extract_http_scheme_host_port(splunkd_uri)
        return HECEventWriter(
            None, session_key, scheme, host, port, hec_uri=hec_uri,
            hec_token=hec_token, **context)

    @retry(exceptions=[binding.HTTPError])
    def _get_hec_config(self, hec_input_name, session_key,
                        scheme, host, port, **context):
        hc = HECConfig(
            session_key, scheme=scheme, host=host, port=port, **context)
        settings = hc.get_settings()
        if utils.is_true(settings.get('disabled')):
            # Enable HEC input
            logging.info('Enabling HEC')
            settings['disabled'] = '0'
            settings['enableSSL'] = context.get('hec_enablessl', '1')
            settings['port'] = context.get('hec_port', '8088')
            hc.update_settings(settings)

        hec_input = hc.get_input(hec_input_name)
        if not hec_input:
            # Create HEC input
            logging.info('Create HEC datainput, name=%s', hec_input_name)
            hinput = {
                'index': context.get('index', 'main'),
            }

            if context.get('sourcetype'):
                hinput['sourcetype'] = context['sourcetype']

            if context.get('token'):
                hinput['token'] = context['token']

            if context.get('source'):
                hinput['source'] = context['source']

            if context.get('host'):
                hinput['host'] = context['host']

            hec_input = hc.create_input(hec_input_name, hinput)

        limits = hc.get_limits()
        HECEvent.max_hec_event_length = int(
            limits.get('max_content_length', 1000000))

        return settings['port'], hec_input['token']

    def create_event(self, data, time=None,
                     index=None, host=None, source=None, sourcetype=None,
                     stanza=None, unbroken=False, done=False):
        '''Create a new HECEvent object.
        '''

        return HECEvent(
            data, time=time,
            index=index, host=host, source=source, sourcetype=sourcetype)

    def write_events(self, events):
        '''Write events to index in bulk.
        :type events: list of Events
        :param events: Event type objects to write.
        '''
        if not events:
            return

        last_ex = None
        for event in HECEvent.format_events(events):
            for i in xrange(self.WRITE_EVENT_RETRIES):
                try:
                    self._rest_client.post(
                        self.HTTP_EVENT_COLLECTOR_ENDPOINT, body=event,
                        headers=self.headers)
                except binding.HTTPError as e:
                    logging.error('Write events through HEC failed: %s.',
                                  traceback.format_exc(e))
                    last_ex = e
                    time.sleep(2 ** (i + 1))
                else:
                    break
            else:
                # When failed after retry, we reraise the exception
                # to exit the function to let client handle this situation
                raise last_ex
