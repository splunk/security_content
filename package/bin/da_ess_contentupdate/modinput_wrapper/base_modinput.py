# encoding = utf-8
import importlib
import copy
import logging
import os
import sys
import json
import tempfile

from solnlib.packages.splunklib import modularinput as smi
from solnlib.log import Logs
from solnlib.modular_input import checkpointer
from solnlib import utils as sutils

from splunktaucclib.global_config import GlobalConfig, GlobalConfigSchema
from splunk_aoblib.rest_helper import TARestHelper
from splunk_aoblib.setup_util import Setup_Util

DATA_INPUTS_OPTIONS = "data_inputs_options"
AOB_TEST_FLAG = 'AOB_TEST'
FIELD_TYPE = "type"
FIELD_FORMAT = "format_type"
CUSTOMIZED_VAR = "customized_var"
TYPE_CHECKBOX = "checkbox"
TYPE_ACCOUNT = "global_account"


class BaseModInput(smi.Script):
    '''
    This is a modular input wrapper, which provides some helper
    functions to read the paramters from setup pages and the arguments
    from input definition
    '''
    LogLevelMapping = {'debug': logging.DEBUG,
                       'info': logging.INFO,
                       'warning': logging.WARNING,
                       'error': logging.ERROR,
                       'critical': logging.CRITICAL}

    def __init__(self, app_namespace, input_name, use_single_instance=False):
        super(BaseModInput, self).__init__()
        self.use_single_instance = use_single_instance
        self._canceled = False
        self.input_type = input_name
        self.input_stanzas = {}
        self.context_meta = {}
        self.namespace = app_namespace
        # redirect all the logging to one file
        Logs.set_context(namespace=app_namespace,
                         root_logger_log_file=input_name)
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.rest_helper = TARestHelper(self.logger)
        # check point
        self.ckpt = None
        self.setup_util = None

    @property
    def app(self):
        return self.get_app_name()

    @property
    def global_setup_util(self):
        """
        This is a private API used in AoB code internally. It is not allowed to be used in user's code.

        :return: setup util instance to read global configurations
        """
        return self.setup_util

    def get_app_name(self):
        """Get TA name.

        :return: the name of TA this modular input is in
        """
        raise NotImplemented

    def get_scheme(self):
        """Get basic scheme, with use_single_instance field set.

        :return: a basic input scheme
        """
        scheme = smi.Scheme(self.input_type)
        scheme.use_single_instance = self.use_single_instance
        return scheme

    def stream_events(self, inputs, ew):
        """The method called to stream events into Splunk.

        This method overrides method in splunklib modular input.
        It pre-processes the input args and call collect_events to stream events.

        :param inputs: An ``InputDefinition`` object.
        :param ew: An object with methods to write events and log messages to Splunk.
        """
        # the input metadata is like
        # {
        #     'server_uri': 'https://127.0.0.1:8089',
        #     'server_host': 'localhost',
        #     'checkpoint_dir': '...',
        #     'session_key': 'ceAvf3z^hZHYxe7wjTyTNo6_0ZRpf5cvWPdtSg'
        # }
        self.context_meta = inputs.metadata
        # init setup util
        uri = inputs.metadata["server_uri"]
        session_key = inputs.metadata['session_key']
        self.setup_util = Setup_Util(uri, session_key, self.logger)

        input_definition = smi.input_definition.InputDefinition()
        input_definition.metadata = copy.deepcopy(inputs.metadata)
        input_definition.inputs = copy.deepcopy(inputs.inputs)
        try:
            self.parse_input_args(input_definition)
        except Exception as e:
            import traceback
            self.log_error(traceback.format_exc(e))
            print >> sys.stderr, traceback.format_exc(e)
            self.input_stanzas = {}
        if not self.input_stanzas:
            # if no stanza found. Just return
            return
        try:
            self.set_log_level(self.log_level)
        except:
            self.log_debug('set log level fails.')
        try:
            self.collect_events(ew)
        except Exception as e:
            import traceback
            self.log_error('Get error when collecting events.\n' + traceback.format_exc(e))
            print >> sys.stderr, traceback.format_exc(e)
            raise RuntimeError(str(e))

    def collect_events(self, event_writer):
        """Collect events and stream to Splunk using event writer provided.

        Note: This method is originally collect_events(self, inputs, event_writer).

        :param event_writer: An object with methods to write events and log messages to Splunk.
        """
        raise NotImplemented()

    def parse_input_args(self, inputs):
        """Parse input arguments, either from os environment when testing or from global configuration.

        :param inputs: An ``InputDefinition`` object.
        :return:
        """
        if os.environ.get(AOB_TEST_FLAG, 'false') == 'true':
            self._parse_input_args_from_env(inputs)
        else:
            self._parse_input_args_from_global_config(inputs)
        if not self.use_single_instance:
            assert len(self.input_stanzas) == 1

    def _parse_input_args_from_global_config(self, inputs):
        """Parse input arguments from global configuration.

        :param inputs:
        """
        dirname = os.path.dirname
        config_path = os.path.join(dirname(dirname(dirname(dirname(__file__)))), 'appserver', 'static', 'js', 'build',
                                   'globalConfig.json')
        with open(config_path) as f:
            schema_json = ''.join([l for l in f])
        global_schema = GlobalConfigSchema(json.loads(schema_json))

        uri = inputs.metadata["server_uri"]
        session_key = inputs.metadata['session_key']
        global_config = GlobalConfig(uri, session_key, global_schema)
        ucc_inputs = global_config.inputs.load(input_type=self.input_type)
        all_stanzas = ucc_inputs.get(self.input_type, {})
        if not all_stanzas:
            # for single instance input. There might be no input stanza.
            # Only the default stanza. In this case, modinput should exit.
            self.log_warning("No stanza found for input type: " + self.input_type)
            sys.exit(0)

        account_fields = self.get_account_fields()
        checkbox_fields = self.get_checkbox_fields()
        self.input_stanzas = {}
        for stanza in all_stanzas:
            full_stanza_name = '{}://{}'.format(self.input_type, stanza.get('name'))
            if full_stanza_name in inputs.inputs:
                if stanza.get('disabled', False):
                    raise RuntimeError("Running disabled data input!")
                stanza_params = {}
                for k, v in stanza.iteritems():
                    if k in checkbox_fields:
                        stanza_params[k] = sutils.is_true(v)
                    elif k in account_fields:
                        stanza_params[k] = copy.deepcopy(v)
                    else:
                        stanza_params[k] = v
                self.input_stanzas[stanza.get('name')] = stanza_params

    def _parse_input_args_from_env(self, inputs):
        """Parse input arguments from os environment. This is used for testing inputs.

        :param inputs:
        """
        data_inputs_options = json.loads(os.environ.get(DATA_INPUTS_OPTIONS, '[]'))
        account_fields = self.get_account_fields()
        checkbox_fields = self.get_checkbox_fields()
        self.input_stanzas = {}
        while len(inputs.inputs) > 0:
            input_stanza, stanza_args = inputs.inputs.popitem()
            kind_and_name = input_stanza.split("://")
            if len(kind_and_name) == 2:
                stanza_params = {}
                for arg_name, arg_value in stanza_args.iteritems():
                    try:
                        arg_value_trans = json.loads(arg_value)
                    except ValueError:
                        arg_value_trans = arg_value
                    stanza_params[arg_name] = arg_value_trans
                    if arg_name in account_fields:
                        stanza_params[arg_name] = self.get_user_credential_by_id(arg_value_trans)
                    elif arg_name in checkbox_fields:
                        stanza_params[arg_name] = sutils.is_true(arg_value_trans)
                self.input_stanzas[kind_and_name[1]] = stanza_params

    def get_account_fields(self):
        """Get the names of account variables.

        Should be implemented in subclass.

        :return: a list of variable names
        """
        raise NotImplemented

    def get_checkbox_fields(self):
        """Get the names of checkbox variables.

        Should be implemented in subclass.

        :return: a list of variable names
        """
        raise NotImplemented

    def get_global_checkbox_fields(self):
        """Get the names of checkbox global parameters.

        :return: a list of global variable names
        """
        raise NotImplemented

    # Global setting related functions.
    # Global settings consist of log setting, proxy, account(user_credential) and customized settings.
    @property
    def log_level(self):
        return self.get_log_level()

    def get_log_level(self):
        """Get the log level configured in global configuration.

        :return: log level set in global configuration or "INFO" by default.
        """
        return self.setup_util.get_log_level()

    def set_log_level(self, level):
        """Set the log level this python process uses.

        :param level: log level in `string`. Accept "DEBUG", "INFO", "WARNING", "ERROR" and "CRITICAL".
        """
        if isinstance(level, basestring):
            level = level.lower()
            if level in self.LogLevelMapping:
                level = self.LogLevelMapping[level]
            else:
                level = logging.INFO
        self.logger.setLevel(level)

    def log(self, msg):
        """Log msg using logging level in global configuration.

        :param msg: log `string`
        """
        self.logger.log(level=self.log_level, msg=msg)

    def log_debug(self, msg):
        """Log msg using logging.DEBUG level.

        :param msg: log `string`
        """
        self.logger.debug(msg)

    def log_info(self, msg):
        """Log msg using logging.INFO level.

        :param msg: log `string`
        """
        self.logger.info(msg)

    def log_warning(self, msg):
        """Log msg using logging.WARNING level.

        :param msg: log `string`
        """
        self.logger.warning(msg)

    def log_error(self, msg):
        """Log msg using logging.ERROR level.

        :param msg: log `string`
        """
        self.logger.error(msg)

    def log_critical(self, msg):
        """Log msg using logging.CRITICAL level.

        :param msg: log `string`
        """
        self.logger.critical(msg)

    @property
    def proxy(self):
        return self.get_proxy()

    def get_proxy(self):
        """Get proxy settings in global configuration.

        Proxy settings include fields "proxy_url", "proxy_port", "proxy_username", "proxy_password", "proxy_type" and "proxy_rdns".

        :return: a `dict` containing proxy parameters or empty `dict` if proxy is not set.
        """
        return self.setup_util.get_proxy_settings()

    def get_user_credential_by_username(self, username):
        """Get global credential information based on username.

        Credential settings include fields "name"(account id), "username" and "password".

        :param username: `string`
        :return: if credential with username exists, return a `dict`, else None.
        """
        return self.setup_util.get_credential_by_username(username)

    def get_user_credential_by_id(self, account_id):
        """Get global credential information based on account id.

        Credential settings include fields "name"(account id), "username" and "password".

        :param account_id: `string`
        :return: if credential with account_id exists, return a `dict`, else None.
        """
        return self.setup_util.get_credential_by_id(account_id)

    def get_global_setting(self, var_name):
        """Get customized setting value configured in global configuration.

        :param var_name: `string`
        :return: customized global configuration value or None
        """
        var_value = self.setup_util.get_customized_setting(var_name)
        if var_value is not None and var_name in self.get_global_checkbox_fields():
            var_value = sutils.is_true(var_value)
        return var_value

    # Functions to help create events.
    def new_event(self, data, time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True):
        """Create a Splunk event object.

        :param data: ``string``, the event's text.
        :param time: ``float``, time in seconds, including up to 3 decimal places to represent milliseconds.
        :param host: ``string``, the event's host, ex: localhost.
        :param index: ``string``, the index this event is specified to write to, or None if default index.
        :param source: ``string``, the source of this event, or None to have Splunk guess.
        :param sourcetype: ``string``, source type currently set on this event, or None to have Splunk guess.
        :param done: ``boolean``, is this a complete ``Event``? False if an ``Event`` fragment.
        :param unbroken: ``boolean``, Is this event completely encapsulated in this ``Event`` object?
        :return: ``Event`` object
        """
        return smi.Event(data=data, time=time, host=host, index=index,
                         source=source, sourcetype=sourcetype, done=done, unbroken=unbroken)

    # Basic get functions. To get params in input stanza.
    def get_input_type(self):
        """Get input type.

        :return: the modular input type
        """
        return self.input_type

    def get_input_stanza(self, input_stanza_name=None):
        """Get input stanzas.

        If stanza name is None, return a dict with stanza name as key and params as values.
        Else return a dict with param name as key and param value as value.

        :param input_stanza_name: None or `string`
        :return: `dict`
        """
        if input_stanza_name:
            return self.input_stanzas.get(input_stanza_name, None)
        return self.input_stanzas

    def get_input_stanza_names(self):
        """Get all stanza names this modular input instance is given.

        For multi instance mode, a single string value will be returned.
        For single instance mode, stanza names will be returned in a list.

        :return: `string` or `list`
        """
        if self.input_stanzas:
            names = self.input_stanzas.keys()
            if self.use_single_instance:
                return names
            else:
                assert len(names) == 1
                return names[0]
        return None

    def get_arg(self, arg_name, input_stanza_name=None):
        """Get the input argument.

        If input_stanza_name is not provided:
            For single instance mode, return a dict <input_name, arg_value>.
            For multi instance mode, return a single value or None.
        If input_stanza_name is provided, return a single value or None.

        :param arg_name: `string`, argument name
        :param input_stanza_name: None or `string`, a stanza name
        :return: `dict` or `string` or None
        """
        if input_stanza_name is None:
            args_dict = {k: args[
                arg_name] for k, args in self.input_stanzas.iteritems() if arg_name in args}
            if self.use_single_instance:
                return args_dict
            else:
                if len(args_dict) == 1:
                    return args_dict.values()[0]
                return None
        else:
            return self.input_stanzas.get(input_stanza_name, {}).get(arg_name, None)

    def get_output_index(self, input_stanza_name=None):
        """Get output Splunk index.

        :param input_stanza_name: `string`
        :return: `string` output index
        """
        return self.get_arg('index', input_stanza_name)

    def get_sourcetype(self, input_stanza_name=None):
        """Get sourcetype to index.

        :param input_stanza_name: `string`
        :return: the sourcetype to index to
        """
        return self.get_arg('sourcetype', input_stanza_name)

    # HTTP request helper
    def send_http_request(self, url, method, parameters=None, payload=None, headers=None, cookies=None, verify=True,
                          cert=None, timeout=None, use_proxy=True):
        """Send http request and get response.

        :param url: URL for the new Request object.
        :param method: method for the new Request object. Can be "GET", "POST", "PUT", "DELETE"
        :param parameters: (optional) Dictionary or bytes to be sent in the query string for the Request.
        :param payload: (optional) Dictionary, bytes, or file-like object to send in the body of the Request.
        :param headers: (optional) Dictionary of HTTP Headers to send with the Request.
        :param cookies: (optional) Dict or CookieJar object to send with the Request.
        :param verify: (optional) whether the SSL cert will be verified. A CA_BUNDLE path can also be provided.
        :param cert: (optional) if String, path to ssl client cert file (.pem). If Tuple, ('cert', 'key') pair.
        :param timeout: (optional) How long to wait for the server to send data before giving up, as a float,
            or a (connect timeout, read timeout) tuple. Default to (10.0, 5.0).
        :param use_proxy: (optional) whether to use proxy. If set to True, proxy in global setting will be used.
        :return: Response
        """
        return self.rest_helper.send_http_request(url=url, method=method, parameters=parameters, payload=payload,
                                                  headers=headers, cookies=cookies, verify=verify, cert=cert,
                                                  timeout=timeout,
                                                  proxy_uri=self._get_proxy_uri() if use_proxy else None)

    def _get_proxy_uri(self):
        uri = None
        proxy = self.get_proxy()
        if proxy and proxy.get('proxy_url') and proxy.get('proxy_type'):
            uri = proxy['proxy_url']
            if proxy.get('proxy_port'):
                uri = '{0}:{1}'.format(uri, proxy.get('proxy_port'))
            if proxy.get('proxy_username') and proxy.get('proxy_password'):
                uri = '{0}://{1}:{2}@{3}/'.format(proxy['proxy_type'], proxy[
                    'proxy_username'], proxy['proxy_password'], uri)
            else:
                uri = '{0}://{1}'.format(proxy['proxy_type'], uri)
        return uri

    # Checkpointing related functions
    def _init_ckpt(self):
        if self.ckpt is None:
            if 'AOB_TEST' in os.environ:
                ckpt_dir = self.context_meta.get('checkpoint_dir', tempfile.mkdtemp())
                if not os.path.exists(ckpt_dir):
                    os.makedirs(ckpt_dir)
                self.ckpt = checkpointer.FileCheckpointer(ckpt_dir)
            else:
                if 'server_uri' not in self.context_meta:
                    raise ValueError('server_uri not found in input meta.')
                if 'session_key' not in self.context_meta:
                    raise ValueError('session_key not found in input meta.')
                dscheme, dhost, dport = sutils.extract_http_scheme_host_port(self.context_meta[
                                                                                 'server_uri'])
                self.ckpt = checkpointer.KVStoreCheckpointer(self.app + "_checkpointer",
                                                             self.context_meta['session_key'], self.app,
                                                             scheme=dscheme, host=dhost, port=dport)

    def get_check_point(self, key):
        """Get checkpoint.

        :param key: `string`
        :return: Checkpoint state if exists else None.
        """
        if self.ckpt is None:
            self._init_ckpt()
        return self.ckpt.get(key)

    def save_check_point(self, key, state):
        """Update checkpoint.

        :param key: Checkpoint key. `string`
        :param state: Checkpoint state.
        """
        if self.ckpt is None:
            self._init_ckpt()
        self.ckpt.update(key, state)

    def batch_save_check_point(self, states):
        """Batch update checkpoint.

        :param states: a `dict` states with chekpoint key as key and checkpoint state as value.
        """
        if self.ckpt is None:
            self._init_ckpt()
        self.ckpt.batch_update(states)

    def delete_check_point(self, key):
        """Delete checkpoint.

        :param key: Checkpoint key. `string`
        """
        if self.ckpt is None:
            self._init_ckpt()
        self.ckpt.delete(key)
