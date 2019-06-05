import copy
import os.path
import traceback

from .common.log import get_cc_logger
from .common.util import load_json_file
from .configuration import get_loader_by_version
from .core import CloudConnectEngine
from .core.exceptions import ConfigException

_logger = get_cc_logger()


class CloudConnectClient(object):
    """The client of cloud connect used to start a cloud connect engine instance.
    """

    def __init__(self, context, config_file, checkpoint_mgr):
        """
        Constructs a `CloudConnectClient` with `context` which contains variables
        to render template in the configuration parsed from file `config_file`.
        :param context: context to render template.
        :param config_file: file path for load user passed interface.
        """
        self._context = context
        self._config_file = config_file
        self._engine = None
        self._config = None
        self._checkpoint_mgr = checkpoint_mgr

    def _load_config(self):
        """Load a JSON based configuration definition from file.
        :return: A `dict` contains user defined JSON interface.
        """
        try:
            conf = load_json_file(self._config_file)
        except:
            raise ConfigException(
                'Unable to load configuration file %s: %s'
                % (self._config_file, traceback.format_exc())
            )

        version = conf.get('meta', {'apiVersion', None}).get('apiVersion', None)
        if not version:
            raise ConfigException(
                'Config meta or api version not present in {}'.format(
                    self._config_file))

        config_loader, schema_file = get_loader_by_version(version)
        schema_path = os.path.join(
            os.path.dirname(__file__), 'configuration', schema_file)

        return config_loader.load(conf, schema_path, self._context)

    def start(self):
        """
        Initialize a new `CloudConnectEngine` instance and start it.
        """
        try:
            if self._config is None:
                self._config = self._load_config()

            self._engine = CloudConnectEngine()
            self._engine.start(
                context=copy.deepcopy(self._context),
                config=self._config,
                checkpoint_mgr=self._checkpoint_mgr
            )
        except Exception as ex:
            _logger.exception('Error while starting client')
            raise ex

    def stop(self):
        """Stop the current cloud connect engine.
        """
        if self._engine:
            self._engine.stop()
