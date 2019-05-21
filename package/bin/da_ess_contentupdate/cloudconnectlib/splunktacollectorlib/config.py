"""UCC Config Module
This is for load/save configuration in UCC server or TA.
The load/save action is based on specified schema.
"""

from __future__ import absolute_import

import json
import logging
import traceback
import time

from ..splunktalib.rest import splunkd_request, code_to_msg
from ..splunktalib.common import util as sc_util

from .common import log as stulog
from .common import UCCException
from urllib import quote

LOGGING_STOPPED = False


def stop_logging():
    """
    Stop Config Logging. This is for not showing REST request error
    while splunkd shutting down.
    :return:
    """
    global LOGGING_STOPPED
    LOGGING_STOPPED = True


def log(msg, msgx='', level=logging.INFO, need_tb=False):
    """
    Logging in UCC Config Module.
    :param msg: message content
    :param msgx: detail info.
    :param level: logging level
    :param need_tb: if need logging traceback
    :return:
    """
    global LOGGING_STOPPED
    if LOGGING_STOPPED:
        return

    msgx = ' - ' + msgx if msgx else ''
    content = 'UCC Config Module: %s%s' % (msg, msgx)
    if need_tb:
        stack = ''.join(traceback.format_stack())
        content = '%s\r\n%s' % (content, stack)
    stulog.logger.log(level, content, exc_info=1)


class ConfigException(UCCException):
    """Exception for UCC Config Exception
    """
    pass


class Config(object):
    """UCC Config Module
    """

    # Placeholder stands for any field
    FIELD_PLACEHOLDER = '*'

    # Head of non-processing endpoint
    NON_PROC_ENDPOINT = '#'

    # Some meta fields in UCC Config schema
    META_FIELDS = ('_product', '_rest_namespace', '_rest_prefix',
                   '_protocol_version', '_version',
                   '_encryption_formatter')

    # Default Values for Meta fields
    META_FIELDS_DEFAULT = {
        '_encryption_formatter': '',
    }

    def __init__(self, splunkd_uri, session_key, schema,
                 user='nobody', app='-'):
        """
        :param splunkd_uri: the root uri of Splunk server,
            like https://127.0.0.1:8089
        :param session_key: session key for Splunk server
        :param schema:
        :param user: owner of the resources requested
        :param app: namespace of the resources requested
        :return:
        """
        self.splunkd_uri = splunkd_uri.strip('/')
        self.session_key = session_key
        self.user, self.app = user, app
        self._parse_schema(schema)
        self._check_protocol_version()

    def load(self):
        """Load Configurations in UCC according to the schema
        It will raise exception if failing to load any endpoint,
        because it make no sense with not complete configuration info.
        """
        log('"load" method in', level=logging.DEBUG)

        ret = {meta_field: getattr(self, meta_field)
               for meta_field in Config.META_FIELDS}

        for ep_id, ep in self._endpoints.iteritems():
            data = {'output_mode': 'json', '--cred--': '1'}

            retries = 4
            waiting_time = [1, 2, 2]
            for retry in xrange(retries):
                resp, cont = splunkd_request(
                    splunkd_uri=self.make_uri(ep_id),
                    session_key=self.session_key,
                    data=data,
                    retry=3
                )

                if resp is None or resp.status != 200:
                    msg = 'Fail to load endpoint "{ep_id}" - {err}' \
                          ''.format(ep_id=ep_id,
                                    err=code_to_msg(resp, cont)
                                    if resp else cont)
                    log(msg, level=logging.ERROR, need_tb=True)
                    raise ConfigException(msg)

                try:
                    ret[ep_id] = self._parse_content(ep_id, cont)
                except ConfigException, exc:
                    log(exc, level=logging.WARNING, need_tb=True)
                    if retry < retries-1:
                        time.sleep(waiting_time[retry])
                else:
                    break
            else:
                log(exc, level=logging.ERROR, need_tb=True)
                raise exc

        log('"load" method out', level=logging.DEBUG)
        return ret

    def update_items(self, endpoint_id, item_names, field_names, data,
                     raise_if_failed=False):
        """Update items in specified endpoint with given fields in data
        :param endpoint_id: endpoint id in schema, the key name in schema
        :param item_names: a list of item name
        :param field_names: a list of updated fields
        :param data: a dict of content for items, for example:
            {
                "item_name_1": {
                    "field_name_1": "value_1",
                    "field_name_2": "value_2",
                },
                "item_name_2": {
                    "field_name_1": "value_1x",
                    "field_name_2": "value_2x",
                }
            }
        :raise_if_failed: raise an exception if updating failed.
        :return: a list of endpoint ids, which are failed to be updated.
            If raise_if_failed is True, it will exist with an exception
            on any updating failed.
        """
        log('"update_items" method in',
            msgx='endpoint_id=%s, item_names=%s, field_names=%s'
                 % (endpoint_id, item_names, field_names),
            level=logging.DEBUG)

        assert endpoint_id in self._endpoints, \
            'Unexpected endpoint id in given schema - {ep_id}' \
            ''.format(ep_id=endpoint_id)

        item_names_failed = []
        for item_name in item_names:
            item_data = data.get(item_name, {})
            item_data = {field_name: self.dump_value(endpoint_id,
                                                     item_name,
                                                     field_name,
                                                     item_data[field_name])
                         for field_name in field_names
                         if field_name in item_data}
            if not item_data:
                continue
            item_uri = self.make_uri(endpoint_id, item_name=item_name)

            resp, cont = splunkd_request(splunkd_uri=item_uri,
                                         session_key=self.session_key,
                                         data=item_data,
                                         method="POST",
                                         retry=3
                                         )
            if resp is None or resp.status not in (200, 201):
                msg = 'Fail to update item "{item}" in endpoint "{ep_id}"' \
                      ' - {err}'.format(ep_id=endpoint_id,
                                        item=item_name,
                                        err=code_to_msg(resp, cont)
                                        if resp else cont)
                log(msg, level=logging.ERROR)
                if raise_if_failed:
                    raise ConfigException(msg)
                item_names_failed.append(item_name)

        log('"update_items" method out', level=logging.DEBUG)
        return item_names_failed

    def make_uri(self, endpoint_id, item_name=None):
        """Make uri for REST endpoint in TA according to given schema
        :param endpoint_id: endpoint id in schema
        :param item_name: item name for given endpoint. None for listing all
        :return:
        """
        endpoint = self._endpoints[endpoint_id]['endpoint']
        ep_full = endpoint[1:].strip('/') \
            if endpoint.startswith(Config.NON_PROC_ENDPOINT) else \
            '{admin_match}/{protocol_version}/{endpoint}' \
            ''.format(admin_match=self._rest_namespace,
                      protocol_version=self._protocol_version,
                      endpoint=(self._rest_prefix +
                                self._endpoints[endpoint_id]['endpoint']))
        ep_uri = None if endpoint_id not in self._endpoints else \
            '{splunkd_uri}/servicesNS/{user}/{app}/{endpoint_full}' \
            ''.format(splunkd_uri=self.splunkd_uri,
                      user=self.user,
                      app=self.app,
                      endpoint_full=ep_full
                      )

        url = ep_uri if item_name is None else "{ep_uri}/{item_name}"\
            .format(ep_uri=ep_uri, item_name=quote(item_name))
        if item_name is None:
            url += '?count=-1'
        log('"make_uri" method', msgx='url=%s' % url,
            level=logging.DEBUG)
        return url

    def _parse_content(self, endpoint_id, content):
        """Parse content returned from REST
        :param content: a JSON string returned from REST.
        """
        try:
            content = json.loads(content)['entry']
            ret = {ent['name']: ent['content'] for ent in content}
        except Exception as exc:
            msg = 'Fail to parse content from endpoint_id=%s' \
                  ' - %s' % (endpoint_id, exc)
            log(msg, level=logging.ERROR, need_tb=True)
            raise ConfigException(msg)

        ret = {name: {key: self.load_value(endpoint_id, name, key, val)
                      for key, val in ent.iteritems()
                      if not key.startswith('eai:')}
               for name, ent in ret.iteritems()}
        return ret

    def _parse_schema(self, ucc_config_schema):
        try:
            ucc_config_schema = json.loads(ucc_config_schema)
        except ValueError:
            msg = 'Invalid JSON content of schema'
            log(msg, level=logging.ERROR, need_tb=True)
            raise ConfigException(msg)
        except Exception as exc:
            log(exc, level=logging.ERROR, need_tb=True)
            raise ConfigException(exc)

        ucc_config_schema.update({key: val for key, val in
                                  Config.META_FIELDS_DEFAULT.iteritems()
                                  if key not in ucc_config_schema})
        for field in Config.META_FIELDS:
            assert field in ucc_config_schema and \
                isinstance(ucc_config_schema[field], basestring), \
                'Missing or invalid field "%s" in given schema' % field
            setattr(self, field, ucc_config_schema[field])

        self._endpoints = {}
        for key, val in ucc_config_schema.iteritems():
            if key.startswith('_'):
                continue

            assert isinstance(val, dict), \
                'The schema of endpoint "%s" should be dict' % key
            assert 'endpoint' in val, \
                'The endpoint "%s" has no endpoint entry' % key

            self._endpoints[key] = val

    def _check_protocol_version(self):
        """
        Check if the protocol version in given schema is supported.
        :return:
        """
        if not self._protocol_version:
            return
        if not self._protocol_version.startswith('1.'):
            raise ConfigException('Unsupported protocol version "%s" '
                                  'in given schema' % self._protocol_version)

    def load_value(self, endpoint_id, item_name, fname, fval):
        field_type = self._get_field_type(endpoint_id, item_name, fname)
        if field_type == '':
            return fval

        try:
            field_type = field_type.lower()
            if field_type == 'bool':
                return True if sc_util.is_true(fval) else False
            elif field_type == 'int':
                return int(fval)
            elif field_type == 'json':
                return json.loads(fval)
        except Exception as exc:
            msg = 'Fail to load value of "{type_name}" - ' \
                  'endpoint={endpoint}, item={item}, field={field}' \
                  ''.format(type_name=field_type,
                            endpoint=endpoint_id,
                            item=item_name,
                            field=fname)
            log(msg, msgx=str(exc), level=logging.WARNING, need_tb=True)
            raise ConfigException(msg)

    def dump_value(self, endpoint_id, item_name, fname, fval):
        field_type = self._get_field_type(endpoint_id, item_name, fname)
        if field_type == '':
            return fval

        try:
            field_type = field_type.lower()
            if field_type == 'bool':
                return str(fval).lower()
            elif field_type == 'json':
                return json.dumps(fval)
            else:
                return fval
        except Exception, exc:
            msg = 'Fail to dump value of "{type_name}" - ' \
                  'endpoint={endpoint}, item={item}, field={field}' \
                  ''.format(type_name=field_type,
                            endpoint=endpoint_id,
                            item=item_name,
                            field=fname)
            log(msg, msgx=str(exc), level=logging.ERROR, need_tb=True)
            raise ConfigException(msg)

    def _get_field_type(self, endpoint_id, item_name, fname):
        field_types = self._endpoints[endpoint_id].get('field_types', {})
        if item_name in field_types:
            fields = field_types[item_name]
        elif Config.FIELD_PLACEHOLDER in field_types:
            fields = field_types[Config.FIELD_PLACEHOLDER]
        else:
            fields = {}

        field_type = fields.get(fname, '')
        if field_type not in ('', 'bool', 'int', 'json'):
            msg = 'Unsupported type "{type_name}" for value in schema - ' \
                  'endpoint={endpoint}, item={item}, field={field}' \
                  ''.format(type_name=field_type,
                            endpoint=endpoint_id,
                            item=item_name,
                            field=fname)
            log(msg, level=logging.ERROR, need_tb=True)
            raise ConfigException(msg)
        return field_type

    def get_endpoints(self):
        return self._endpoints
