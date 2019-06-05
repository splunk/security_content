
import json
import traceback
from urlparse import urlparse
from solnlib.splunkenv import get_splunkd_uri
from solnlib.splunk_rest_client import SplunkRestClient
from solnlib.conf_manager import ConfManager
from splunktaucclib.rest_handler.error import RestError
from splunktaucclib.rest_handler.admin_external import (
    AdminExternalHandler,
)
from splunktaucclib.rest_handler import util


def _migrate_error_handle(func):
    def handle(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            raise RestError(
                500,
                'Migrating failed. %s' % traceback.format_exc()
            )

    return handle


class ConfigMigrationHandler(AdminExternalHandler):
    """
    REST handler, which will migrate configuration
    from add-on built by previous version of TAB (v2.0.0).
    """

    def handleList(self, confInfo):
        self._migrate()
        # use classic inheritance to be compatible for
        # old version of Splunk private SDK
        AdminExternalHandler.handleList(self, confInfo)

    @_migrate_error_handle
    def _migrate(self):
        internal_endpoint = self.endpoint.internal_endpoint
        if not (internal_endpoint.endswith('settings') or
                internal_endpoint.endswith('account')):
            return

        splunkd_info = urlparse(get_splunkd_uri())
        self.base_app_name = util.get_base_app_name()
        self.conf_mgr = ConfManager(
            self.getSessionKey(),
            self.base_app_name,
            scheme=splunkd_info.scheme,
            host=splunkd_info.hostname,
            port=splunkd_info.port,
        )
        self.client = SplunkRestClient(
            self.getSessionKey(),
            self.base_app_name,
            scheme=splunkd_info.scheme,
            host=splunkd_info.hostname,
            port=splunkd_info.port,
        )
        self.legacy_passwords = None

        # migration legacy configuration in related conf files
        if internal_endpoint.endswith('settings'):
            self._migrate_conf()
            self._migrate_conf_customized()
        elif internal_endpoint.endswith('account'):
            self._migrate_conf_credential()

    def get_legacy_passwords(self):
        if self.legacy_passwords is None:
            self.legacy_passwords = {}
            for pwd in self.client.storage_passwords.list(count=-1):
                if pwd.realm == self.base_app_name:
                    self.legacy_passwords[pwd.username] = pwd
        return self.legacy_passwords

    def _migrate_conf(self):
        """
        Migrate from <TA-name>.conf to <prefix>_settings.conf
        :return:
        """
        if self.callerArgs.id not in ('logging', 'proxy'):
            return
        conf_file_name = self.base_app_name
        conf_file, stanzas = self._load_conf(conf_file_name)
        if not stanzas:
            return

        # migrate: global_settings ==> logging
        if 'global_settings' in stanzas and self.callerArgs.id == 'logging':
            stanza = stanzas['global_settings']
            if 'log_level' in stanza:
                stanza['loglevel'] = stanza['log_level']
                del stanza['log_level']
            name = 'logging'
            response = self.handler.update(
                name,
                self._filter_stanza(name, stanza),
            )
            self._loop_response(response)
            # delete legacy configuration
            self._delete_legacy(conf_file, {'global_settings': None})

        # migrate: proxy_settings ==> proxy
        if 'proxy_settings' in stanzas and self.callerArgs.id == 'proxy':
            name = 'proxy'
            response = self.handler.update(
                name,
                self._filter_stanza(name, stanzas['proxy_settings']),
            )
            self._loop_response(response)
            # delete legacy configuration
            self._delete_legacy(conf_file, {'proxy_settings': None})

    def _migrate_conf_customized(self):
        """
        Migrate from <TA-name>_customized.conf to <prefix>_settings.conf
        :return:
        """
        if self.callerArgs.id != 'additional_parameters':
            return

        conf_file_name = self.base_app_name + '_customized'
        conf_file, stanzas = self._load_conf(conf_file_name)
        if not stanzas:
            return

        additional_parameters = {}
        for stanza_name, stanza in stanzas.iteritems():
            for key, val in stanza.iteritems():
                if key == 'type':
                    continue
                else:
                    additional_parameter = val
                    break
            else:
                continue
            if additional_parameter:
                additional_parameters[stanza_name] = additional_parameter

        name = 'additional_parameters'
        response = self.handler.update(
            name,
            self._filter_stanza(name, additional_parameters),
        )
        self._loop_response(response)

        # delete legacy configuration
        self._delete_legacy(conf_file, stanzas)

    def _migrate_conf_credential(self):
        """
        Migrate from <TA-name>_credential.conf to <prefix>_account.conf
        :return:
        """
        conf_file_name = self.base_app_name + '_credential'
        conf_file, stanzas = self._load_conf(conf_file_name)

        for stanza_name, stanza in stanzas.iteritems():
            stanza['username'] = stanza_name
            response = self.handler.create(
                stanza_name,
                stanza,
            )
            self._loop_response(response)

        # delete legacy configuration
        self._delete_legacy(conf_file, stanzas)

    def _load_conf(self, conf_file_name):
        if conf_file_name not in self.client.confs:
            return None, {}
        conf_file = self.conf_mgr.get_conf(conf_file_name)
        stanzas = conf_file.get_all()
        for stanza_name, stanza in stanzas.iteritems():
            pwd = self.get_legacy_passwords().get(stanza_name)
            if pwd:
                pwd_cont = json.loads(pwd.clear_password)
                stanza.update(pwd_cont)
            for key in stanza.keys():
                if key.startswith('eai:') or key == 'disabled':
                    del stanza[key]

        return conf_file, stanzas

    def _delete_legacy(self, conf_file, stanzas):
        for stanza_name, _ in stanzas.iteritems():
            try:
                # delete stanza from related conf file
                conf_file.delete(stanza_name)
            except Exception:
                pass

            pwd = self.get_legacy_passwords().get(stanza_name)
            try:
                # delete password from passwords.conf
                if pwd:
                    pwd.delete()
            except Exception:
                pass

    def _filter_stanza(self, stanza_name, stanza):
        model = self.endpoint.model(stanza_name, stanza)
        stanza_new = {
            f.name: stanza[f.name] for f in model.fields if f.name in stanza
        }
        return stanza_new

    @classmethod
    def _loop_response(cls, response):
        for _ in response:
            pass
