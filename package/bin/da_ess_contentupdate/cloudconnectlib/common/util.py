import json
from ..splunktalib.common import util
from solnlib.modular_input.event import XMLEvent


def is_valid_bool(val):
    """Check whether a string can be convert to bool.
    :param val: value as string.
    :return: `True` if value can be convert to bool else `False`.
    """
    return util.is_true(val) or util.is_false(val)


def is_true(val):
    return util.is_true(val)


def is_valid_port(port):
    """Check whether a port is valid.
    :param port: port to check.
    :return: `True` if port is valid else `False`.
    """
    try:
        return 1 <= int(port) <= 65535
    except ValueError:
        return False


def load_json_file(file_path):
    """
    Load a dict from a JSON file.
    :param file_path: JSON file path.
    :return: A `dict` object.
    """
    with open(file_path, 'r') as file_pointer:
        return json.load(file_pointer)


def format_events(raw_events, time=None,
                  index=None, host=None, source=None, sourcetype=None,
                  stanza=None, unbroken=False, done=False):
    return XMLEvent.format_events(XMLEvent(data, time=time,
                                           index=index, host=host,
                                           source=source,
                                           sourcetype=sourcetype,
                                           stanza=stanza, unbroken=unbroken,
                                           done=done) for data in
                                  raw_events)
