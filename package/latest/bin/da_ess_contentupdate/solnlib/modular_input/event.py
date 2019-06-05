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
This module provides Splunk modular input event encapsulation.
'''

import json
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

__all__ = ['EventException',
           'XMLEvent',
           'HECEvent']


class EventException(Exception):
    pass


class Event(object):
    '''Base class of modular input event.
    '''

    def __init__(self, data, time=None,
                 index=None, host=None, source=None, sourcetype=None,
                 stanza=None, unbroken=False, done=False):
        '''Modular input event.

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
        :type unbroken: ``bool``
        :param done: (optional) The last unbroken event, default is False.
        :returns: ``bool``

        Usage::
           >>> event = Event(
           >>>     data='This is a test data.',
           >>>     time=1372274622.493,
           >>>     index='main',
           >>>     host='localhost',
           >>>     source='Splunk',
           >>>     sourcetype='misc',
           >>>     stanza='test_scheme://test',
           >>>     unbroken=True,
           >>>     done=True)
        '''

        self._data = data
        self._time = '%.3f' % time if time else None
        self._index = index
        self._host = host
        self._source = source
        self._sourcetype = sourcetype
        self._stanza = stanza
        if not unbroken and done:
            raise EventException(
                'Invalid combination of "unbroken" and "done".')
        self._unbroken = unbroken
        self._done = done

    def __str__(self):
        return json.dumps({
            'data': self._data,
            'time': float(self._time) if self._time else self._time,
            'index': self._index,
            'host': self._host,
            'source': self._source,
            'sourcetype': self._sourcetype,
            'stanza': self._stanza,
            'unbroken': self._unbroken,
            'done': self._done
        })

    @classmethod
    def format_events(cls, events):
        '''Format events to list of string.

        :param events: List of events to format.
        :type events: ``list``
        :returns: List of formated events string.
        :rtype: ``list``
        '''

        raise EventException('Unimplemented "format_events".')


class XMLEvent(Event):
    '''XML event.
    '''

    def _to_xml(self):
        _event = ET.Element('event')
        if self._stanza:
            _event.set('stanza', self._stanza)
        if self._unbroken:
            _event.set('unbroken', str(int(self._unbroken)))

        if self._time:
            ET.SubElement(_event, 'time').text = self._time

        sub_elements = [('index', self._index),
                        ('host', self._host),
                        ('source', self._source),
                        ('sourcetype', self._sourcetype)]
        for node, value in sub_elements:
            if value:
                ET.SubElement(_event, node).text = value

        if isinstance(self._data, (unicode, basestring)):
            ET.SubElement(_event, 'data').text = self._data
        else:
            ET.SubElement(_event, 'data').text = json.dumps(self._data)

        if self._done:
            ET.SubElement(_event, 'done')

        return _event

    @classmethod
    def format_events(cls, events):
        '''Output: [
        '<stream>
        <event stanza="test_scheme://test" unbroken="1">
        <time>1459919070.994</time>
        <index>main</index>
        <host>localhost</host>
        <source>test</source>
        <sourcetype>test</sourcetype>
        <data>{"kk": [1, 2, 3]}</data>
        <done />
        </event>
        <event stanza="test_scheme://test" unbroken="1">
        <time>1459919082.961</time>
        <index>main</index>
        <host>localhost</host>
        <source>test</source>
        <sourcetype>test</sourcetype>
        <data>{"kk": [3, 2, 3]}</data>
        <done />
        </event>
        </stream>']
        '''

        stream = ET.Element('stream')
        for event in events:
            stream.append(event._to_xml())

        return [ET.tostring(stream, encoding='utf-8', method='xml')]


class HECEvent(Event):
    '''HEC event.
    '''

    max_hec_event_length = 1000000

    def _to_hec(self):
        event = {}
        event['event'] = self._data
        if self._time:
            event['time'] = float(self._time)
        if self._index:
            event['index'] = self._index
        if self._host:
            event['host'] = self._host
        if self._source:
            event['source'] = self._source
        if self._sourcetype:
            event['sourcetype'] = self._sourcetype

        return json.dumps(event)

    @classmethod
    def format_events(cls, events):
        '''Output: [
        '{"index": "main", ... "event": {"kk": [1, 2, 3]}}\\n
        {"index": "main", ... "event": {"kk": [3, 2, 3]}}',
        '...']
        '''

        size = 0
        new_events, batched_events = [], []
        events = [event._to_hec() for event in events]
        for event in events:
            new_length = size + len(event) + len(batched_events) - 1
            if new_length >= cls.max_hec_event_length:
                if batched_events:
                    new_events.append('\n'.join(batched_events))
                del batched_events[:]
                size = 0

            batched_events.append(event)
            size = size + len(event)
        if batched_events:
            new_events.append('\n'.join(batched_events))

        return new_events
