"""APP Cloud Connect errors"""


class ConfigException(Exception):
    """Config exception"""
    pass


class FuncException(Exception):
    """Ext function call exception"""
    pass


class HTTPError(Exception):
    """ HTTPError raised when HTTP request returned a error."""

    def __init__(self, reason=None):
        """
        Initialize HTTPError with `response` object and `status`.
        """
        self.reason = reason
        super(HTTPError, self).__init__(reason)


class StopCCEIteration(Exception):
    """Exception to exit from the engine iteration."""
    pass
