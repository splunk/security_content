import json
import os

import solnlib.utils as utils

from splunktaucclib.global_config import GlobalConfig, GlobalConfigSchema


'''
Usage Examples:
setup_util = Setup_Util(uri, session_key)
setup_util.get_log_level()
setup_util.get_proxy_settings()
setup_util.get_credential_account("my_account_name")
setup_util.get_customized_setting("my_customized_field_name")
'''

'''
setting object structure.
It is stored in self.__cached_global_settings
Note, this structure is only maintained in this util.
setup_util transforms global settings in os environment or from ucc into this structure.
{
    "proxy_settings": {
    "proxy_enabled": False/True,
    "proxy_url": "example.com",
    "proxy_port": "1234",
    "proxy_username": "",
    "proxy_password": "",
    "proxy_type": "http",
    "proxy_rdns": False/True
    },
    "log_settings": {
        "loglevel": "DEBUG"
    },
    "credential_settings": [{
        "name": "account_id",
        "username": "example_account",
        "password": "example_password"
    }, { # supported by ucc, not seen any usage in AoB
        "api_key": "admin",
        "api_uuid": "admin",
        "endpoint": "some url",
        "name": "account1"
    }],
    "customized_settings": {
        "text_name": "content",
        "pass_name": "password",
        "checkbox": 0/1
    }
}
'''

GLOBAL_SETTING_KEY = "global_settings"
AOB_TEST_FLAG = 'AOB_TEST'

PROXY_SETTINGS = "proxy_settings"
LOG_SETTINGS = "log_settings"
CREDENTIAL_SETTINGS = "credential_settings"
CUSTOMIZED_SETTINGS = "customized_settings"

UCC_PROXY = "proxy"
UCC_LOGGING = "logging"
UCC_CUSTOMIZED = "additional_parameters"
UCC_CREDENTIAL = "account"

CONFIGS = [CREDENTIAL_SETTINGS]
SETTINGS = [PROXY_SETTINGS, LOG_SETTINGS, CUSTOMIZED_SETTINGS]

PROXY_ENABLE_KEY = 'proxy_enabled'
PROXY_RDNS_KEY = 'proxy_rdns'
LOG_LEVEL_KEY = 'loglevel'
LOG_LEVEL_KEY_ENV = 'log_level'

TYPE_CHECKBOX = "checkbox"
ALL_SETTING_TYPES = ['text', 'password', 'checkbox', 'dropdownlist', 'multi_dropdownlist', 'radiogroup']


def get_schema_path():
    dirname = os.path.dirname
    basedir = dirname(dirname(dirname((dirname(__file__)))))
    return os.path.join(basedir, 'appserver', 'static', 'js', 'build', 'globalConfig.json')


class Setup_Util(object):
    def __init__(self, uri, session_key, logger=None):
        self.__uri = uri
        self.__session_key = session_key
        self.__logger = logger
        self.scheme, self.host, self.port = utils.extract_http_scheme_host_port(
            self.__uri)
        self.__cached_global_settings = {}
        self.__global_config = None

    def init_global_config(self):
        if self.__global_config is not None:
            return
        schema_file = get_schema_path()
        if not os.path.isfile(schema_file):
            self.log_error("Global config JSON file not found!")
            self.__global_config = None
        else:
            with open(get_schema_path()) as f:
                json_schema = ''.join([l for l in f])
            self.__global_config = GlobalConfig(self.__uri, self.__session_key,
                                                GlobalConfigSchema(json.loads(json_schema)))

    def log_error(self, msg):
        if self.__logger:
            self.__logger.error(msg)

    def log_info(self, msg):
        if self.__logger:
            self.__logger.info(msg)

    def log_debug(self, msg):
        if self.__logger:
            self.__logger.debug(msg)

    def _parse_conf(self, key):
        if os.environ.get(AOB_TEST_FLAG, 'false') == 'true':
            global_settings = self._parse_conf_from_env(json.loads(os.environ.get(GLOBAL_SETTING_KEY, '{}')))
            return global_settings.get(key)
        else:
            return self._parse_conf_from_global_config(key)

    def _parse_conf_from_env(self, global_settings):
        '''
        this is run in test env
        '''
        if not self.__cached_global_settings:
            # format the settings, the setting from env is from global_setting
            # meta
            self.__cached_global_settings = {}
            for s_k, s_v in global_settings.iteritems():
                if s_k == PROXY_SETTINGS:
                    proxy_enabled = s_v.get(PROXY_ENABLE_KEY)
                    proxy_rdns = s_v.get(PROXY_RDNS_KEY)
                    if type(proxy_enabled) != bool:
                        s_v[PROXY_ENABLE_KEY] = utils.is_true(proxy_enabled)
                    if type(proxy_rdns) != bool:
                        s_v[PROXY_RDNS_KEY] = utils.is_true(proxy_rdns)
                    self.__cached_global_settings[PROXY_SETTINGS] = s_v
                elif s_k == LOG_SETTINGS:
                    self.__cached_global_settings[LOG_SETTINGS] = {
                        LOG_LEVEL_KEY: s_v.get(LOG_LEVEL_KEY_ENV)
                    }
                elif s_k == CREDENTIAL_SETTINGS:
                    # add account id to accounts
                    for i in range(0, len(s_v)):
                        s_v[i]['name'] = 'account' + str(i)
                    self.__cached_global_settings[CREDENTIAL_SETTINGS] = s_v
                else:  # should be customized settings
                    self.__cached_global_settings[CUSTOMIZED_SETTINGS] = {}
                    for s in s_v:
                        field_type = s.get('type')
                        if not field_type:
                            self.log_error(
                                'unknown type for customized var:{}'.format(s))
                            continue
                        self.__cached_global_settings['customized_settings'][s.get('name', '')] = self._transform(
                            s.get("value", ""), field_type)

        return self.__cached_global_settings

    def _parse_conf_from_global_config(self, key):
        if self.__cached_global_settings and key in self.__cached_global_settings:
            return self.__cached_global_settings.get(key)
        self.init_global_config()
        if self.__global_config is None:
            return None
        if key in CONFIGS:
            accounts = self.__global_config.configs.load().get(UCC_CREDENTIAL, [])
            if accounts:
                for account in accounts:
                    if 'disabled' in account:
                        del account['disabled']
            self.__cached_global_settings[CREDENTIAL_SETTINGS] = accounts
        elif key in SETTINGS:
            settings = self.__global_config.settings.load()
            self.__cached_global_settings.update({UCC_PROXY: None, UCC_LOGGING: None, UCC_CUSTOMIZED: None})
            customized_setting = {}
            for setting in settings.get('settings', []):
                # filter out disabled setting page and 'disabled' field
                if setting.get('disabled', False):
                    continue
                if setting['name'] == UCC_LOGGING:
                    self.__cached_global_settings[LOG_SETTINGS] = {
                        LOG_LEVEL_KEY: setting.get(LOG_LEVEL_KEY)
                    }
                elif setting['name'] == UCC_PROXY:
                    if 'disabled' in setting:
                        del setting['disabled']
                    setting[PROXY_ENABLE_KEY] = utils.is_true(setting.get(PROXY_ENABLE_KEY, '0'))
                    setting[PROXY_RDNS_KEY] = utils.is_true(setting.get(PROXY_RDNS_KEY, '0'))
                    self.__cached_global_settings[PROXY_SETTINGS] = setting
                else:  # should be customized settings
                    if 'disabled' in setting:
                        del setting['disabled']
                    customized_setting.update(setting)
            self.__cached_global_settings[CUSTOMIZED_SETTINGS] = customized_setting

        return self.__cached_global_settings.get(key)

    def get_log_level(self):
        log_level = "INFO"
        log_settings = self._parse_conf(LOG_SETTINGS)
        if log_settings is None:
            self.log_info("Log level is not set, use default INFO")
        else:
            log_level = log_settings.get(LOG_LEVEL_KEY, None)
            if not log_level:
                self.log_info("Log level is not set, use default INFO")
                log_level = "INFO"
        return log_level

    def get_proxy_settings(self):
        proxy_settings = self._parse_conf(PROXY_SETTINGS)
        if proxy_settings is None:
            self.log_info("Proxy is not set!")
            return {}
        proxy_enabled = proxy_settings.get(PROXY_ENABLE_KEY)
        if not proxy_enabled:
            self.log_info("Proxy is not enabled!")
            return {}
        proxy_settings = {
            "proxy_url": proxy_settings.get("proxy_url", ""),
            "proxy_port": proxy_settings.get("proxy_port", None),
            "proxy_username": proxy_settings.get("proxy_username", ""),
            "proxy_password": proxy_settings.get("proxy_password", ""),
            "proxy_type": proxy_settings.get("proxy_type", ""),
            "proxy_rdns": proxy_settings.get("proxy_rdns")
        }
        self._validate_proxy_settings(proxy_settings)
        return proxy_settings

    def get_credential_by_id(self, account_id):
        credential_settings = self._parse_conf(CREDENTIAL_SETTINGS)
        for account in credential_settings:
            if account.get('name', None) == account_id:
                return account
        self.log_error("Credential account with account id {} can not be found".format(account_id))
        return None

    def get_credential_by_username(self, username):
        credential_settings = self._parse_conf(CREDENTIAL_SETTINGS)
        for account in credential_settings:
            if account.get('username', None) == username:
                return account
        self.log_error("Credential account with username {} can not be found".format(username))
        return None

    def get_customized_setting(self, key):
        customized_settings = self._parse_conf(CUSTOMIZED_SETTINGS)
        if customized_settings is None:
            self.log_info("Customized setting is not set")
            return None
        if key not in customized_settings:
            self.log_info("Customized key can not be found")
            return None
        customized_setting = customized_settings.get(key, None)
        if customized_setting is None:
            self.log_error("Cannot find customized setting with key %s" % key)
        return customized_setting

    def _validate_proxy_settings(self, proxy_settings):
        if proxy_settings:
            if proxy_settings.get('proxy_url') == "":
                raise Exception("Proxy host must not be empty!")
            proxy_port = proxy_settings.get('proxy_port')
            if proxy_port is None or not proxy_port.isdigit():
                raise Exception("Proxy port must a number!")

    def _transform(self, value, field_type):
        '''
        This is method is only used when parsing customized global params from env.
        Only checkbox type needs transform. Other types will be extracted automatically when apply json.loads.
        :param value:
        :param field_type: can be checkbox, text, password, dropdownlist, multi_dropdownlist, radiogroup
        :return:
        '''
        if field_type == TYPE_CHECKBOX:
            return utils.is_true(value)
        elif field_type in ALL_SETTING_TYPES:
            return value
        else:
            raise Exception("Type of this customized setting is corrupted. Value: {}, type: {}"
                            .format(value, field_type))


    '''
    # the following methods is used by AoB internally
    # user should not use this
    # These methods returns the similiar structure like ucc libs

    the output of config is like
{
  "account": [
    {
      "username": "admin",
      "credential": "a",
      "name": "ddddd",
      "disabled": false
    }
  ]
}

    the output of settings is like
{
  "settings": [
    {
      "additional_parameters": {
        "checkbox": "1",
        "text": "msn",
        "disabled": false
      }
    },
    {
      "proxy": {
        "proxy_type": "http",
        "proxy_port": "9999",
        "proxy_url": "localhost",
        "proxy_rdns": "1",
        "disabled": false,
        "proxy_password": "a",
        "proxy_username": "admin",
        "proxy_enabled": "1"
      }
    },
    {
      "logging": {
        "loglevel": "ERROR",
        "disabled": false
      }
    }
  ]
}
    '''
    def get_ucc_log_setting(self):
        return {UCC_LOGGING: self._parse_conf(LOG_SETTINGS)}

    def get_ucc_proxy_setting(self):
        p = dict(self.get_proxy_settings())
        p[PROXY_ENABLE_KEY] = True if p else False
        return {
            UCC_PROXY: p
        }


    def get_ucc_customized_setting(self):
        customized_settings = self._parse_conf(CUSTOMIZED_SETTINGS)
        if customized_settings:
            return {
                UCC_CUSTOMIZED: customized_settings
            }
        else:
            return {}

    # account belongs to the configs
    def get_ucc_account_config(self):
        return {
            UCC_CREDENTIAL: self._parse_conf(CREDENTIAL_SETTINGS)
        }
